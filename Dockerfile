# syntax=docker/dockerfile:1
#
# Two images from one Dockerfile:
#   --target mcp      (default) read-only MCP server over HTTP; Node only, no scanners
#   --target scanner  devsecops-scan CLI + Opengrep, OSV-Scanner, Trivy, Nuclei, Katana (Jenkins agent)
#
# Tool versions, rules and templates are pinned; bump them deliberately.
ARG NODE_IMAGE=node:22.23.3-bookworm-slim
ARG GO_IMAGE=golang:1.27.1-bookworm
ARG TRIVY_IMAGE=aquasec/trivy:0.75.0
ARG NUCLEI_IMAGE=projectdiscovery/nuclei:v3.11.1
ARG OPENGREP_VERSION=v1.30.1
ARG OPENGREP_SHA256=d3195b9d8d5ae93179f6aa5f5daaba6a920a5a09d38c5d5ae5e60924050210c4
# opengrep-rules has no release tags; pin a commit.
ARG OPENGREP_RULES_COMMIT=f1d2b562b414783763fd02a6ed2736eaed622efa
ARG OSV_SCANNER_VERSION=v2.6.0
ARG KATANA_VERSION=v1.8.0
ARG NUCLEI_TEMPLATES_VERSION=v10.5.0

# ---- application build -------------------------------------------------------------------
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

# ---- scanner binaries, rules and templates -------------------------------------------------
FROM ${GO_IMAGE} AS tools
ARG OPENGREP_VERSION
ARG OPENGREP_SHA256
ARG OPENGREP_RULES_COMMIT
ARG OSV_SCANNER_VERSION
ARG KATANA_VERSION
ARG NUCLEI_TEMPLATES_VERSION
# Go modules are checksum-verified against sum.golang.org; CGO off gives static binaries.
RUN CGO_ENABLED=0 GOBIN=/out go install "github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}" \
 && CGO_ENABLED=0 GOBIN=/out go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
RUN curl -fsSL -o /out/opengrep "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/opengrep_manylinux_x86" \
 && echo "${OPENGREP_SHA256}  /out/opengrep" | sha256sum -c - \
 && chmod 0755 /out/opengrep
RUN git clone --quiet --depth 1 --branch "${NUCLEI_TEMPLATES_VERSION}" https://github.com/projectdiscovery/nuclei-templates.git /out/nuclei-templates \
 && rm -rf /out/nuclei-templates/.git \
 && git init --quiet /out/opengrep-rules \
 && git -C /out/opengrep-rules fetch --quiet --depth 1 https://github.com/opengrep/opengrep-rules.git "${OPENGREP_RULES_COMMIT}" \
 && git -C /out/opengrep-rules checkout --quiet FETCH_HEAD \
 && rm -rf /out/opengrep-rules/.git

FROM ${TRIVY_IMAGE} AS trivy
FROM ${NUCLEI_IMAGE} AS nuclei

# ---- scanner image (Jenkins agent / Kubernetes Job) ---------------------------------------
FROM ${NODE_IMAGE} AS scanner
# Go binaries need a CA bundle for HTTPS (Trivy DB, OSV API); the slim image has none.
COPY --from=tools /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=tools /out/opengrep /out/osv-scanner /out/katana /usr/local/bin/
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei
COPY --from=tools /out/opengrep-rules /opt/opengrep-rules
COPY --from=tools /out/nuclei-templates /opt/nuclei-templates

WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY src/config ./src/config
RUN printf '#!/bin/sh\nexec node /app/dist/src/cli.js "$@"\n' > /usr/local/bin/devsecops-scan \
 && chmod 0755 /usr/local/bin/devsecops-scan \
 && mkdir -p /workspace /var/cache/trivy \
 && chown node:node /workspace /var/cache/trivy

ENV NODE_ENV=production \
    LANG=C.UTF-8 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    OPENGREP_RULES_DIR=/opt/opengrep-rules \
    NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates \
    TRIVY_CACHE_DIR=/var/cache/trivy \
    SCAN_WORKSPACE_ROOTS=/workspace \
    REPORTS_DIR=/workspace/security-reports

# uid 1000 (node) matches the MCP image, so both can share the reports volume.
# Opengrep unpacks its runtime under $HOME/.cache, so HOME must be writable.
USER node
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
