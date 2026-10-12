# DevSecOps MCP

Self-hosted security scanning for CI pipelines, with a read-only MCP server for AI-assisted triage.

- **Jenkins runs the scanners directly** through one CLI, `devsecops-scan`: Semgrep and SonarQube (SAST), OSV-Scanner and Trivy (SCA), Trivy (container images) and OWASP ZAP (DAST).
- **Every result is stored as JSON and SARIF** under `security-reports/<scan_id>/`, and a **real security gate** (thresholds in `security-rules.yml`) sets the CLI exit code that passes or fails the build.
- **The MCP server only reads results.** It lists and summarizes them for an LLM client, evaluates the policy and renders reports. It cannot start scans or fetch URLs. It runs over authenticated HTTP or stdio.
- **Everything is self-hosted**: Docker Compose for a workstation, Kustomize manifests for Kubernetes.

```
Jenkins / K8s Job ── devsecops-scan ──► Semgrep · SonarQube · OSV-Scanner · Trivy · ZAP
                          │
                          ▼  JSON + SARIF + policy.json            exit code 0 / 1 / 2
                 security-reports/<scan_id>/  ─────────────────────► build gate
                          │  (read-only mount)
                          ▼
          MCP server (HTTP + bearer token) ◄──── Claude / any MCP client (triage)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design, data flow and threat model.

## Contents

- [Components](#components)
- [Quick start (Docker Compose)](#quick-start-docker-compose)
- [The `devsecops-scan` CLI](#the-devsecops-scan-cli)
- [Security policy](#security-policy)
- [Jenkins](#jenkins)
- [Kubernetes](#kubernetes)
- [Connecting MCP clients](#connecting-mcp-clients)
- [Configuration reference](#configuration-reference)
- [Development](#development)
- [Troubleshooting](#troubleshooting)

## Components

| Scan type | Tool | How it runs | Default |
|---|---|---|---|
| `sast` | Semgrep 1.179 | CLI (`semgrep scan --json`) | ✔ |
| `sast` | SonarQube Community 26.9 | `sonar-scanner` 8.1, then the Web API (CE task, quality gate, issues) | |
| `sca` | OSV-Scanner 2.6 | CLI (`osv-scanner scan source`) | ✔ |
| `sca` | Trivy 0.75 | CLI (`trivy fs`: vulnerabilities, secrets, misconfigurations) | |
| `container` | Trivy 0.75 | CLI (`trivy image`) | ✔ |
| `dast` | OWASP ZAP (daemon) | ZAP API: spider, passive scan; `full` mode adds the active scan | ✔ |

Commercial connectors (Snyk, Veracode, Contrast), the mocked IAST tool, `npm audit` and the scan-triggering MCP tools were removed in v2.

Images (one `Dockerfile`, two targets):

- `--target mcp` (default): the MCP server only. Node 22, non-root, no scanners.
- `--target scanner`: the CLI plus all scanners and a JVM for `sonar-scanner`. Use it as the Jenkins agent or Kubernetes Job image.

## Quick start (Docker Compose)

Requirements: Docker with Compose v2, about 6 GB of RAM for SonarQube, and `vm.max_map_count=524288` on Linux hosts (`sudo sysctl -w vm.max_map_count=524288`).

```bash
cp .env.example .env
# fill in MCP_AUTH_TOKEN, SONAR_DB_PASSWORD and ZAP_API_KEY, e.g. with: openssl rand -hex 32
mkdir -p security-reports

docker compose up -d --build          # mcp, sonarqube, postgres, zap
docker compose ps                     # wait until everything is healthy
```

Compose refuses to start while a required secret is missing. All published ports bind to `127.0.0.1`.

SonarQube needs a one-time setup: open <http://127.0.0.1:9000>, log in as `admin`/`admin`, change the password, create a **Global Analysis Token** (My Account → Security) and put it in `.env` as `SONAR_TOKEN`.

Run scans with the scanner image. `SCAN_SOURCE` in `.env` picks the source tree; the default is `./test-samples`, which contains deliberately vulnerable code.

```bash
docker compose run --rm scanner devsecops-scan sast --target /workspace/src
docker compose run --rm scanner devsecops-scan sca  --target /workspace/src --tool trivy
docker compose run --rm scanner devsecops-scan sast --target /workspace/src --tool sonarqube --project-key demo

# DAST against the bundled vulnerable demo app
docker compose --profile demo up -d dast-target
docker compose run --rm scanner devsecops-scan dast --target http://dast-target:3001/
```

Then check the MCP server:

```bash
curl -s http://127.0.0.1:3000/health                     # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3000/mcp   # 401 without a token
```

## The `devsecops-scan` CLI

```
devsecops-scan <sast|sca|container|dast> --target <path|image|url> [options]
devsecops-scan gate   --scan-id <id> [--scan-id <id> ...]
devsecops-scan report --scan-id <id> [...] [--format markdown|json|sarif] [--out file]
```

| Option | Meaning |
|---|---|
| `--target` | `sast`/`sca`: a directory inside an allowed workspace root. `container`: an image reference. `dast`: an http(s) URL. |
| `--tool` | Overrides the scan type's `default_tool`. |
| `--scan-id` | Explicit id (`[a-z0-9_-]`, 3–128 characters). Generated when omitted. Existing ids are never overwritten. |
| `--project-key` | SonarQube project key (required with `--tool sonarqube`). |
| `--zap-mode` | `baseline` (spider + passive scan) or `full` (adds the active scan; only use it against test environments). |
| `--no-fail` | Exit 0 on a policy FAIL so later scans still run; a single `gate` decides at the end. |
| `--rules`, `--reports-dir` | Override `SECURITY_RULES_PATH` and `REPORTS_DIR`. |

**Exit codes:** `0` = policy PASS (or WARN under permissive enforcement), `1` = policy FAIL, `2` = scanner, usage or configuration error. A scanner error is still stored as a `failed` result, so the gate never passes on missing evidence.

Each scan writes:

```
security-reports/<scan_id>/
  result.json    normalized result: summary + findings (severity, rule, location, fix, CWE/CVE)
  result.sarif   SARIF 2.1.0 for Jenkins Warnings NG, IDEs and code-scanning UIs
  policy.json    gate decision for this scan
```

Guards built into the CLI:

- Targets must resolve (symlinks included) inside `SCAN_WORKSPACE_ROOTS`.
- Targets that look like flags are refused.
- Scanners run without a shell, with `--` before the target, a timeout and a size cap on their output.
- DAST URLs pass an SSRF guard. Loopback, link-local and cloud-metadata (169.254.169.254) addresses are refused unless explicitly allowlisted.

## Security policy

[`src/config/security-rules.yml`](src/config/security-rules.yml) is loaded with `yaml` and validated with Joi; unknown keys are errors.

```yaml
global_policy:
  enforcement_level: strict      # permissive = report violations as WARN, exit 0
  thresholds: { critical: 0, high: 0, medium: 5, low: 20 }   # omit or null = unlimited
sast:
  thresholds: { critical: 0, high: 0, medium: 5 }            # overrides global per severity
  require_sonar_quality_gate: true
dast:
  target_policy:
    allowed_hosts: ["*.staging.example.com"]                  # once set, only these are scanned
    allowed_cidrs: ["10.20.0.0/16"]
```

The gate fails when any of the following is true:

- a severity count exceeds its threshold;
- a scan failed;
- no results were given;
- the data is incomplete or inconsistent (for example, a summary that under-counts its findings);
- SonarQube's quality gate is not `OK` while `require_sonar_quality_gate` is on.

Semgrep's registry rulesets need egress to semgrep.dev. On air-gapped runners, point `sast.semgrep.configs` at local rules. [`src/config/semgrep/baseline.yml`](src/config/semgrep/baseline.yml) is a small offline starter set.

## Jenkins

[`Jenkinsfile`](Jenkinsfile) is a ready-to-adapt pipeline:

1. Build and push the scanner image: `docker build --target scanner -t registry.example.com/devsecops-scanner:2.0.0 .`
2. Install the plugins Docker Pipeline, Credentials Binding, Timestamper, Warnings Next Generation and Lockable Resources.
3. Add the credentials `sonar-token` and `zap-api-key` (kind: Secret text) if you use SonarQube or DAST.
4. Create a Pipeline job from SCM and set the parameters (`SCANNER_IMAGE`, `RUN_SONAR`, `IMAGE_REF`, `DAST_TARGET_URL`, ...).

The pipeline runs Semgrep, OSV-Scanner and Trivy in parallel, plus SonarQube and the Trivy image scan when enabled. DAST runs under a `zap-daemon` lock because the daemon holds a single session. The stage `devsecops-scan gate` fails the build on exit code 1 or 2. Reports are archived and the SARIF files are published with Warnings NG.

For Kubernetes agents, swap the agent block for `deploy/k8s/jenkins/scanner-pod.yaml` (the comment in the Jenkinsfile shows how).

## Kubernetes

```bash
kubectl create namespace devsecops
kubectl -n devsecops create secret generic devsecops-secrets \
  --from-literal=mcp-auth-token="$(openssl rand -hex 32)" \
  --from-literal=sonar-db-password="$(openssl rand -hex 24)" \
  --from-literal=zap-api-key="$(openssl rand -hex 24)"
# set your registry in deploy/k8s/base/kustomization.yaml (images:), then
kubectl apply -k deploy/k8s/base
```

What the base deploys:

- **MCP** (Deployment + Service). Read-only root filesystem, drop ALL capabilities, read-only reports mount, token taken from a Secret file, no egress.
- **SonarQube** (StatefulSet) with a `vm.max_map_count` initContainer, and **PostgreSQL** (StatefulSet).
- **ZAP daemon** (Deployment + Service).
- The shared **`security-reports` PVC** (ReadWriteMany; see the file for ReadWriteOnce guidance).
- **NetworkPolicies**:
  - default deny for ingress;
  - MCP only accepts traffic from namespaces labelled `devsecops.io/mcp-client=true`;
  - SonarQube and ZAP only accept pods labelled `devsecops.io/scanner=true`;
  - Postgres only accepts SonarQube.

`deploy/k8s/examples/scan-job.yaml` shows an on-demand scan Job. It clones a repo, runs the scans and the gate, and writes the results to the PVC.

The SonarQube initContainer is privileged. If your cluster forbids that, delete it, set the sysctl on the nodes, and enforce Pod Security `restricted` on the namespace.

## Connecting MCP clients

Tools (all read-only):

| Tool | Purpose |
|---|---|
| `list_scans` | Stored scans, newest first, with severity counts. Filter by `scan_type`. |
| `get_scan_result` | One result. Findings sorted by severity, filtered by `min_severity`, paginated. |
| `summarize_findings` | Triage view across scans: totals, findings grouped by rule with example locations and fixes, and the policy decision. |
| `validate_security_policy` | PASS/WARN/FAIL with reasons for a set of scan ids. |
| `generate_security_report` | Consolidated markdown, json or sarif report. |

Finding text comes from scanned code and target responses, so treat it as untrusted. The tool descriptions tell the model the same thing.

**HTTP** (Compose/Kubernetes). Claude Code example:

```bash
claude mcp add --transport http devsecops http://127.0.0.1:3000/mcp \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

**stdio** (local, reading `./security-reports`), for example in a Claude Desktop config:

```json
{
  "mcpServers": {
    "devsecops": {
      "command": "node",
      "args": ["/path/to/DevSecOps-MCP/dist/src/mcp/server.js"],
      "env": { "REPORTS_DIR": "/path/to/security-reports" }
    }
  }
}
```

## Configuration reference

| Variable | Used by | Default | Meaning |
|---|---|---|---|
| `MCP_TRANSPORT` | MCP | `stdio` | `stdio` or `http` (`--http` also works) |
| `MCP_AUTH_TOKEN` / `MCP_AUTH_TOKEN_FILE` | MCP | (required for http) | Bearer token, at least 32 characters |
| `MCP_HOST`, `MCP_PORT` | MCP | `127.0.0.1`, `3000` | Listen address (the image sets `0.0.0.0`) |
| `MCP_ALLOWED_HOSTS` | MCP | (empty) | Comma-separated Host header allowlist (DNS-rebinding protection) |
| `MCP_MAX_RESPONSE_BYTES` | MCP | `1048576` | Cap on a single tool response |
| `REPORTS_DIR` | both | `./security-reports` | Results directory |
| `SECURITY_RULES_PATH` | both | `src/config/security-rules.yml` | Policy file |
| `SCAN_WORKSPACE_ROOTS` | CLI | current directory | Allowed scan roots (path-separator list) |
| `SEMGREP_PATH`, `TRIVY_PATH`, `OSV_SCANNER_PATH`, `SONAR_SCANNER_PATH` | CLI | binary name | Scanner binaries |
| `TRIVY_CACHE_DIR` | CLI | Trivy default | Vulnerability DB cache |
| `SONAR_HOST_URL`, `SONAR_TOKEN` / `SONAR_TOKEN_FILE` | CLI | `http://localhost:9000` | SonarQube |
| `ZAP_URL`, `ZAP_API_KEY` / `ZAP_API_KEY_FILE` | CLI | `http://localhost:8080` | ZAP daemon API |
| `SCAN_MAX_OUTPUT_MB` | CLI | `64` | Cap on a scanner's stdout |
| `LOG_LEVEL` | both | `info` | Logs go to stderr as JSON |

## Development

```bash
npm ci
npm run build        # tsc -> dist/
npm run typecheck    # src + tests
npm run lint         # ESLint 9 + typescript-eslint
npm test             # Jest: unit + integration (a real MCP client over HTTP, the CLI with stub scanners)
npm run scan -- sast --target test-samples   # needs semgrep on PATH
```

When `semgrep` is installed, the test suite also runs it for real against `test-samples/` (gate fails) and `src/core/` (gate passes). `test-samples/vulnerable-server.js` is a deliberately vulnerable DAST target that binds to `127.0.0.1` unless `HOST` is set.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `compose` says a variable is missing | Fill in `.env` (copy it from `.env.example`). Secrets have no defaults on purpose. |
| SonarQube restarts with `max file descriptors` or `vm.max_map_count` | Raise `ulimit -n` (Compose already sets 131072) and `sysctl -w vm.max_map_count=524288` on the host. |
| SonarQube logs `flood stage disk watermark` | Free disk space. Elasticsearch locks its indices above 95% disk usage. |
| `EACCES` writing `security-reports` | The scanner runs as uid 1000. `chown 1000:1000 security-reports`, or set `SCAN_UID`/`SCAN_GID`. |
| `Target path is outside the allowed workspace` | Scan inside `SCAN_WORKSPACE_ROOTS` (in Jenkins this is `$WORKSPACE`). |
| `blocked address` for a DAST target | Use the staging host's real name, or add it to `dast.target_policy`. |
| `osv-scanner exited with code 127 ... api.osv.dev` | The runner needs egress to `api.osv.dev`, or use `--tool trivy`. |
| Semgrep cannot download `p/...` rulesets | Allow egress to semgrep.dev, or use local rules (`src/config/semgrep/baseline.yml`). |
| Port 3000 or 9000 already in use | Set `MCP_PORT` / `SONAR_PORT` in `.env`. |

## License

MIT, see [LICENSE](LICENSE).
