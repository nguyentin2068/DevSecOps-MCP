# DevSecOps MCP

Self-hosted security scanning for CI pipelines, with a read-only MCP server for AI-assisted triage.

- **Jenkins runs the scanners directly** through one CLI, `devsecops-scan`:
  - **SAST:** Opengrep
  - **SCA:** OSV-Scanner and Trivy
  - **Container images:** Trivy
  - **DAST:** Nuclei, with Katana crawling for the fuzzing pass
- **Every result is stored as JSON and SARIF** under `security-reports/<scan_id>/`. A **real security gate** (thresholds in `security-rules.yml`) sets the CLI exit code that passes or fails the build.
- **The MCP server is optional and only reads results.** It lists and summarizes them for an LLM client, evaluates the policy and renders reports. It cannot start scans or fetch URLs. It runs over authenticated HTTP or stdio.
- **Everything is self-hosted** and needs no long-running scanner services: Docker Compose for a workstation, Kustomize manifests for Kubernetes.

```
Jenkins / K8s Job ── devsecops-scan ──► Opengrep · OSV-Scanner · Trivy · Nuclei (+ Katana crawl)
                          │
                          ▼  JSON + SARIF + policy.json            exit code 0 / 1 / 2
                 security-reports/<scan_id>/  ─────────────────────► build gate
                          │  (read-only mount)
                          ▼
          MCP server (HTTP + bearer token) ◄──── Claude / any MCP client (triage)
```

**Documentation:**

- [docs/DEPLOYMENT-GUIDE.md](docs/DEPLOYMENT-GUIDE.md): step-by-step setup for Docker Compose, Jenkins and Kubernetes, policy decisions before go-live, a verification checklist and operations.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): design, data flow and threat model.

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

| Scan type | Tool | How it runs |
|---|---|---|
| `sast` | [Opengrep](https://github.com/opengrep/opengrep) 1.30 (LGPL fork of Semgrep CE) | `opengrep scan --json --taint-intrafile`, with the bundled rules plus [opengrep-rules](https://github.com/opengrep/opengrep-rules) pinned to a commit |
| `sca` (default) | OSV-Scanner 2.6 | `osv-scanner scan source` |
| `sca` | Trivy 0.75 | `trivy fs`: vulnerabilities, secrets, misconfigurations |
| `container` | Trivy 0.75 | `trivy image` |
| `dast` | Nuclei 3.11 + Katana 1.8 | `baseline`: Nuclei's HTTP templates (nuclei-templates v10.5.0) against the target URL. `full`: also Katana crawls the target (same origin only) and Nuclei's fuzzing (DAST) templates attack the crawled URLs that have parameters |

SonarQube, OWASP ZAP and Semgrep were removed in this version (see [Migrating](#migrating-from-semgrep-sonarqube-and-zap)).

Images (one `Dockerfile`, two targets):

- `--target mcp` (default): the MCP server only. Node 22, non-root, no scanners.
- `--target scanner`: the CLI, all scanners, opengrep-rules and nuclei-templates (pinned), non-root uid 1000. No Python, no JVM. Use it as the Jenkins agent or Kubernetes Job image.

## Quick start (Docker Compose)

Trying it on one machine takes a few minutes. For production setups (registry, Jenkins, Kubernetes, TLS), follow the [deployment guide](docs/DEPLOYMENT-GUIDE.md).

The scanner works on its own. The MCP server is an optional add-on for AI triage, and nothing in the scan or gate path depends on it.

```bash
mkdir -p security-reports
docker compose build scanner          # the scanner image; no .env needed
```

Run scans with the scanner image. `SCAN_SOURCE` in `.env` picks the source tree; the default is `./test-samples`, which contains deliberately vulnerable code.

```bash
docker compose run --rm scanner devsecops-scan sast --target /workspace/src
docker compose run --rm scanner devsecops-scan sca  --target /workspace/src --tool trivy

# DAST against the bundled vulnerable demo app
docker compose --profile demo up -d dast-target
docker compose run --rm scanner devsecops-scan dast --target http://dast-target:3001/
```

Results are written to `./security-reports/<scan_id>/` as JSON + SARIF. Render them with `docker compose run --rm scanner devsecops-scan report --scan-id <id> --format markdown`, open the `.sarif` files in an IDE (for example the VS Code SARIF Viewer), or publish them in Jenkins.

**Optional: add the MCP server** (profile `mcp`) to let an AI assistant read and triage those results:

```bash
cp .env.example .env                  # set MCP_AUTH_TOKEN (openssl rand -hex 32)
docker compose --profile mcp up -d --build mcp
curl -s http://127.0.0.1:3000/health                     # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3000/mcp   # 401 without a token
```

## The `devsecops-scan` CLI

```
devsecops-scan detect --target <dir> [--format list|json] [--out file]
devsecops-scan <sast|sca|container|dast> --target <path|image|url> [options]
devsecops-scan gate   --scan-id <id> [--scan-id <id> ...]
devsecops-scan report --scan-id <id> [...] [--format markdown|json|sarif] [--out file]
```

| Option | Meaning |
|---|---|
| `--target` | `sast`/`sca`: a directory inside an allowed workspace root. `container`: an image reference. `dast`: an http(s) URL. |
| `--tool` | Overrides the scan type's `default_tool` (only `sca` has a choice: `osv-scanner` or `trivy`). |
| `--scan-id` | Explicit id (`[a-z0-9_-]`, 3–128 characters). Generated when omitted. Existing ids are never overwritten. |
| `--languages` | `sast` only. Comma-separated languages whose rule sets to run (the output of `detect`), `all`, or `""` for the common rules only. Omitted: `sast` detects the languages itself. |
| `--dast-mode` | `baseline` (Nuclei HTTP templates against the target) or `full` (adds a Katana crawl and the fuzzing templates on crawled URLs with parameters; active attacks, only against test environments). |
| `--no-fail` | Exit 0 on a policy FAIL so later scans still run; a single `gate` decides at the end. |
| `--quiet` | Do not stream the scanners' own logs, and run each scanner in its quiet mode. |
| `--rules`, `--reports-dir` | Override `SECURITY_RULES_PATH` and `REPORTS_DIR`. |

**Language detection:** `detect` walks the target (skipping `sast.opengrep.exclude` directories and `.git`, without following symlinks) and counts files per language by extension (`Dockerfile*` counts as `dockerfile`). It prints a per-language table to stderr. On stdout it prints the comma-separated languages that have rule sets in `sast.opengrep.language_configs`, ready for `--languages`; `--format json` prints the full detection instead, and `--out` also writes the JSON to a file. A detected language without rules is shown in the table but not scanned with language rules. For example:

```bash
LANGS=$(docker compose run --rm -T scanner devsecops-scan detect --target /workspace/src)
docker compose run --rm scanner devsecops-scan sast --target /workspace/src --languages "$LANGS"
```

The languages used are recorded in the SAST result's `metadata.languages`.

**Rule IDs:** SAST findings use project rule IDs of the form `sast-<language>-<NNNN>` (for example `sast-python-0006`), grouped by language, instead of Opengrep's path-based ids such as `opt.opengrep-rules.python.django.security.injection.sql.sql-injection-using-raw`. The Opengrep id is kept in the finding's `original_rule_id` (and in the SARIF rule properties).

- The bundled rules (`src/config/opengrep/baseline.yml`) carry their project IDs directly: `sast-javascript-0001`–`0006` (they also cover TypeScript) and `sast-python-0001`–`0005`. Their old names are kept in `metadata.former_id`.
- opengrep-rules is mapped through the catalog `src/config/opengrep/rule-ids.json` (`sast.opengrep.rule_ids`). The language is the rule's top-level directory in opengrep-rules, so `generic/secrets` rules become `sast-generic-NNNN`.
- IDs are stable. When you bump `OPENGREP_RULES_COMMIT`, run `npm run rules:ids -- --rules-dir <checkout of that commit> --source opengrep-rules@<commit>`. Existing rules keep their numbers, new rules get the next free number of their language, and the numbers of removed rules are never reused. `--check` exits 1 when a rule has no ID.
- Rules from your own rule files that are not in the catalog keep Opengrep's id and are listed in the result's `metadata.unmapped_rule_ids`. Give them project IDs by naming them `sast-<language>-<NNNN>` directly, as `baseline.yml` does.
- Inline suppressions are matched by Opengrep, so they take the Opengrep rule name (the last part of `original_rule_id`), not the project ID: `// nosemgrep: sql-injection-using-raw`. For the bundled rules, the two are the same.

**Scanner logs:** while a scan runs, the CLI streams each scanner's own log to stderr, one line at a time with the tool name as a prefix, together with the exact command line and the exit status:

```
[opengrep] $ opengrep scan --json --disable-version-check --taint-intrafile --config ... -- /workspace/src
[opengrep] ...the scanner's own progress and warnings...
[opengrep] exited with 1 after 18.4s
```

Each scanner's own quiet mode is turned off for this: Trivy runs with `--no-progress` instead of `--quiet`, and Nuclei and Katana run without `-silent`. ANSI escapes and control characters are stripped, because the lines can echo file names and responses from the scanned target. Stdout keeps only the CLI's summary, so the two streams can be redirected separately (`2> scan.log`). Pass `--quiet` to turn the log off.

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
- Flag-like targets and options are refused.
- Scanners run without a shell, with `--` before the target, a timeout and a size cap on their output.
- DAST targets pass an SSRF guard. Loopback, link-local and cloud-metadata (169.254.169.254) addresses are refused unless explicitly allowlisted.
- Katana results are filtered to the target's own origin before Nuclei sees them.
- Nuclei runs with no out-of-band (interactsh) callbacks, no redirects, HTTP templates only, `dos`/`intrusive` tags excluded, and raw requests/responses omitted from the output.

## Security policy

[`src/config/security-rules.yml`](src/config/security-rules.yml) is loaded with `yaml` and validated with Joi; unknown keys are errors.

```yaml
global_policy:
  enforcement_level: strict      # permissive = report violations as WARN, exit 0
  thresholds: { critical: 0, high: 0, medium: 5, low: 20 }   # omit or null = unlimited
sast:
  thresholds: { critical: 0, high: 0, medium: null, low: null }   # overrides global; null = report only
  opengrep:
    taint_intrafile: true
    configs: [opengrep/baseline.yml, "${OPENGREP_RULES_DIR}/generic/secrets"]   # always run
    language_configs:                                                           # only for scanned languages
      python: ["${OPENGREP_RULES_DIR}/python"]
      typescript: ["${OPENGREP_RULES_DIR}/javascript", "${OPENGREP_RULES_DIR}/typescript"]
      # ... one entry per language in opengrep-rules
dast:
  thresholds: { critical: 0, high: 0, medium: 0 }            # reflected XSS / open redirect are medium
  mode: baseline
  crawl: { enabled: true, max_depth: 3, max_duration_seconds: 300, max_urls: 500 }
  nuclei: { exclude_tags: [dos, intrusive], rate_limit: 50 }
  target_policy:
    allowed_hosts: ["*.staging.example.com"]                  # once set, only these are scanned
    allowed_cidrs: ["10.20.0.0/16"]
```

Relative rule paths resolve against the rules file's directory, and `${VAR}` expands from the environment. The scanner image sets `OPENGREP_RULES_DIR` and `NUCLEI_TEMPLATES_DIR`; a referenced variable that is unset is an error.

The gate fails when any of the following is true:

- a severity count exceeds its threshold;
- a scan failed;
- no results were given;
- the data is incomplete or inconsistent (for example, a summary that under-counts its findings).

**Default thresholds and tuning:**

- **SAST:** only `critical` and `high` gate the build. opengrep-rules is broad and on a typical codebase reports many medium/low findings that are false positives (for example `path-join-resolve-traversal` on guarded code), so `medium` and `low` are `null`: recorded in the reports and SARIF, not enforced. Only the rule sets of the detected languages run; remove a `language_configs` entry to stop scanning that language. Suppress reviewed findings inline (`// nosemgrep: <rule-id>`), then set `medium` to a number to start enforcing it.
- **DAST:** Nuclei rates confirmed reflected XSS and open redirects as `medium`, so `medium: 0` fails the build on them. `info` findings (technology fingerprints, missing headers) are never gated.
- **SCA and container:** unchanged (`critical`/`high` at 0; SCA allows up to 3 medium and 10 low).

## Jenkins

[`Jenkinsfile`](Jenkinsfile) is a ready-to-adapt pipeline:

1. Build and push the scanner image: `docker build --target scanner -t registry.example.com/devsecops-scanner:2.1.0 .`
2. Install the plugins Docker Pipeline, Timestamper and Warnings Next Generation.
3. Create a Pipeline job from SCM and set the parameters (`SCANNER_IMAGE`, `IMAGE_REF`, `DAST_TARGET_URL`, `DAST_MODE`).

A pre-check stage runs `devsecops-scan detect` on the checkout and passes the languages it finds to the SAST stage (`--languages`), so Opengrep only loads the rule sets for those languages plus the common rules. The detection is archived as `security-reports/languages-<prefix>.json`. The pipeline then runs Opengrep, OSV-Scanner and Trivy in parallel, plus the Trivy image scan when `IMAGE_REF` is set. DAST runs when `DAST_TARGET_URL` is set. It needs no credentials and no shared daemon. The stage `devsecops-scan gate` fails the build on exit code 1 or 2. Reports are archived and the SARIF files are published with Warnings NG.

**Results for the MCP server:** set `MCP_REPORTS_DIR` (a Jenkins global or node environment variable) to a directory that is mounted on the agent and that the MCP server also mounts. After each build, the `post` step copies that build's scan directories there. It copies to a temporary name and then renames, so the MCP server never sees a partial result, and it never overwrites. Without the variable, results are only archived in Jenkins. See [deployment guide §5.4](docs/DEPLOYMENT-GUIDE.md#54-deliver-results-to-the-mcp-server).

For Kubernetes agents, swap the agent block for `deploy/k8s/jenkins/scanner-pod.yaml` (the comment in the Jenkinsfile shows how). The pod template satisfies the namespace's `restricted` Pod Security standard, including the injected `jnlp` container.

## Kubernetes

```bash
kubectl create namespace devsecops
kubectl -n devsecops create secret generic devsecops-secrets \
  --from-literal=mcp-auth-token="$(openssl rand -hex 32)"
# point an overlay at your registry and storage class (deployment guide §6.1), then
kubectl apply -k deploy/k8s/overlays/prod
```

What the base deploys:

- **MCP** (Deployment + Service). Read-only root filesystem, drop ALL capabilities, read-only reports mount, token taken from a Secret file, no egress.
- The shared **`security-reports` PVC** (ReadWriteMany; see the file for ReadWriteOnce guidance).
- **NetworkPolicies**: default deny for ingress; MCP only accepts traffic from namespaces labelled `devsecops.io/mcp-client=true`.
- The namespace enforces the Pod Security `restricted` standard.

Two on-demand scan Job examples:

- `deploy/k8s/examples/scan-job.yaml` clones a repo, runs the scans and the gate, and writes the results to the PVC shared with the MCP server.
- `deploy/k8s/examples/scan-job-standalone.yaml` needs neither the MCP server nor the base manifests: it prints the markdown report to the logs, and the Job status is the gate result.

**Without the MCP server**, skip the base entirely: use the Jenkins pod template or the standalone Job in any namespace.

Scanner pods carry the label `devsecops.io/scanner=true`. Use it to restrict their egress, for example DAST only to your staging CIDRs. The full walkthrough (overlay, storage class, Ingress with TLS, Jenkins agents writing to the PVC) is in [deployment guide §6](docs/DEPLOYMENT-GUIDE.md#6-topology-c-kubernetes).

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
| `MCP_REPORTS_DIR` | Jenkinsfile | (unset) | Optional directory, shared with the MCP server, that each build's results are copied into |
| `REPORTS_DIR` | both | `./security-reports` | Results directory |
| `SECURITY_RULES_PATH` | both | `src/config/security-rules.yml` | Policy file |
| `SCAN_WORKSPACE_ROOTS` | CLI | current directory | Allowed scan roots (path-separator list) |
| `OPENGREP_RULES_DIR`, `NUCLEI_TEMPLATES_DIR` | CLI | set in the scanner image | Rule and template locations referenced from the policy file |
| `OPENGREP_PATH`, `OSV_SCANNER_PATH`, `TRIVY_PATH`, `KATANA_PATH`, `NUCLEI_PATH` | CLI | binary name | Scanner binaries |
| `TRIVY_CACHE_DIR` | CLI | Trivy default | Vulnerability DB cache |
| `TRIVY_DB_REPOSITORY`, `TRIVY_JAVA_DB_REPOSITORY` | CLI (read by Trivy) | `mirror.gcr.io`, then `ghcr.io` | Point Trivy at an internal mirror of its databases |
| `SCAN_MAX_OUTPUT_MB` | CLI | `64` | Cap on a scanner's stdout |
| `LOG_LEVEL` | both | `info` | Logs go to stderr as JSON |

## Development

```bash
npm ci
npm run build        # tsc -> dist/
npm run typecheck    # src + tests
npm run lint         # ESLint 9 + typescript-eslint
npm test             # Jest: unit + integration (a real MCP client over HTTP, the CLI with stub scanners)
npm run scan -- sast --target test-samples   # needs opengrep on PATH (or OPENGREP_PATH) and OPENGREP_RULES_DIR
```

When `opengrep` is available (on `PATH` or via `OPENGREP_PATH`), the test suite also runs it for real against `test-samples/` (gate fails) and `src/core/` (gate passes, bundled rules only). `test-samples/vulnerable-server.js` is a deliberately vulnerable DAST target that binds to `127.0.0.1` unless `HOST` is set.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Rules file references ${OPENGREP_RULES_DIR}, which is not set` | Run inside the scanner image, or set the variable to a checkout of opengrep-rules (or nuclei-templates for `NUCLEI_TEMPLATES_DIR`). |
| Opengrep fails with `'ascii' codec can't decode` | The CLI already forces `LANG=C.UTF-8`; if you call opengrep directly, set a UTF-8 locale. |
| Opengrep cannot write `~/.cache/opengrep` | It unpacks its runtime there on first use: make `HOME` writable (the Jenkinsfile uses `$WORKSPACE@tmp/home`). |
| DAST takes too long | The template pass sends roughly 11,700 HTTP templates (nuclei-templates v10.5.0) to the target. Set `nuclei.include_tags` (for example `misconfig,exposure,cve`) or `severities`, raise `rate_limit` if the target can take it, and in full mode lower `crawl.max_urls`. |
| `EACCES` writing `security-reports` | The scanner runs as uid 1000. `chown 1000:1000 security-reports`, or set `SCAN_UID`/`SCAN_GID`. |
| `Target path is outside the allowed workspace` | Scan inside `SCAN_WORKSPACE_ROOTS` (in Jenkins this is `$WORKSPACE`). |
| `blocked address` for a DAST target | Use the staging host's real name, or add it to `dast.target_policy`. |
| `osv-scanner exited with code 127 ... api.osv.dev` | The runner needs egress to `api.osv.dev`, or use `--tool trivy`. |
| A scan fails or hangs and the reason is unclear | Read the `[tool]` lines on stderr: they show the exact command line, the scanner's own log and its exit status. Rerun without `--quiet` if it was set. |
| Port 3000 already in use | Set `MCP_PORT` in `.env`. |

## Migrating from Semgrep, SonarQube and ZAP

- **Policy file:** `sast.semgrep` is now `sast.opengrep`. `sast.require_sonar_quality_gate` and `sast.sonarqube` are gone, and `dast.zap` is replaced by `dast.mode`, `dast.crawl` and `dast.nuclei`. Unknown keys are rejected, so the old file fails validation with a clear message.
- **CLI:** `--project-key` and `--zap-mode` are gone; use `--dast-mode`. Tool names are `opengrep` and `nuclei`.
- **Rules:** Semgrep registry packs (`p/...`) are still passed through to Opengrep, but they are covered by the Semgrep Rules License. The default now uses rules shipped in the image.
- **Coverage changes:** Nuclei finds known CVEs, misconfigurations and exposures well. It is weaker than ZAP's active scan at finding new injection bugs in custom code, even with `--dast-mode full`. SonarQube's dashboards, coverage metrics and hotspot review have no replacement here.

## License

MIT, see [LICENSE](LICENSE).
