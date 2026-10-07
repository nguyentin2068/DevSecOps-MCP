# syntax=docker/dockerfile:1
#
# Two images from one Dockerfile:
#   --target mcp      (default) read-only MCP server over HTTP; Node only, no scanners
#   --target scanner  devsecops-scan CLI + Semgrep, Trivy, OSV-Scanner, sonar-scanner (Jenkins agent)
#
# Tool versions are pinned; bump them deliberately.
ARG NODE_IMAGE=node:22.23.3-bookworm-slim
ARG PYTHON_IMAGE=python:3.12.15-slim-bookworm
ARG GO_IMAGE=golang:1.27.1-bookworm
ARG TRIVY_IMAGE=aquasec/trivy:0.75.0
ARG SONAR_SCANNER_IMAGE=sonarsource/sonar-scanner-cli:12.2.0.4256_8.1.0
ARG OSV_SCANNER_VERSION=v2.6.0
ARG SEMGREP_VERSION=1.179.0

# ---- application build -------------------------------------------------------------------
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

# ---- scanner binaries ----------------------------------------------------------------------
FROM ${GO_IMAGE} AS osv
ARG OSV_SCANNER_VERSION
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}

FROM ${TRIVY_IMAGE} AS trivy
FROM ${SONAR_SCANNER_IMAGE} AS sonar
FROM ${NODE_IMAGE} AS node

# ---- scanner image (Jenkins agent / Kubernetes Job) ---------------------------------------
FROM ${PYTHON_IMAGE} AS scanner
ARG SEMGREP_VERSION
RUN python -m venv /opt/semgrep \
 && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
 && groupadd --gid 1000 scanner \
 && useradd --uid 1000 --gid scanner --create-home --shell /usr/sbin/nologin scanner

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=osv /out/osv-scanner /usr/local/bin/osv-scanner
COPY --from=sonar /opt/sonar-scanner /opt/sonar-scanner
COPY --from=sonar /usr/lib/jvm/java-21-amazon-corretto /opt/java

WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY src/config ./src/config
RUN printf '#!/bin/sh\nexec node /app/dist/src/cli.js "$@"\n' > /usr/local/bin/devsecops-scan \
 && chmod 0755 /usr/local/bin/devsecops-scan \
 && mkdir -p /workspace /var/cache/trivy \
 && chown scanner:scanner /workspace /var/cache/trivy

ENV NODE_ENV=production \
    JAVA_HOME=/opt/java \
    SONAR_SCANNER_HOME=/opt/sonar-scanner \
    PATH=/opt/sonar-scanner/bin:/opt/java/bin:${PATH} \
    TRIVY_CACHE_DIR=/var/cache/trivy \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    SEMGREP_SEND_METRICS=off \
    SCAN_WORKSPACE_ROOTS=/workspace \
    REPORTS_DIR=/workspace/security-reports

USER 1000:1000
WORKDIR /workspace
CMD ["devsecops-scan", "--help"]

# ---- MCP server image (default target) ----------------------------------------------------
FROM ${NODE_IMAGE} AS mcp
WORKDIR /app
COPY --from=build --chown=root:root /app/package.json ./
COPY --from=build --chown=root:root /app/node_modules ./node_modules
COPY --from=build --chown=root:root /app/dist ./dist
COPY --chown=root:root src/config ./src/config
RUN mkdir -p /app/security-reports && chown node:node /app/security-reports

ENV NODE_ENV=production \
    MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=3000 \
    REPORTS_DIR=/app/security-reports \
    LOG_LEVEL=info

# The node user (uid 1000) cannot modify the application files, only the reports volume.
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.MCP_PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["node", "dist/src/mcp/server.js"]
