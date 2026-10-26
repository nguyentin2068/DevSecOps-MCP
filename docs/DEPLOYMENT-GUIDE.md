# Deployment Guide

Step-by-step setup for the DevSecOps scanner and the optional read-only MCP server. Pick one of three topologies, follow its section end to end, then finish with [the verification checklist](#9-verification-checklist).

> **The MCP server is optional.** Scanning, the security gate, the JSON/SARIF results, markdown reports and Jenkins publishing all work without it. Without MCP, skip [3](#3-generate-secrets), [4.2](#42-optional-start-the-mcp-server), [5.4](#54-deliver-results-to-the-mcp-server), [6.1–6.4](#6-topology-c-kubernetes) and [8](#8-connect-mcp-clients).

| Topology | Use it when | Sections |
|---|---|---|
| **A. Single host (Docker Compose)** | Trying it out, a small team, or one build server | 1 → 2 → 3 → 4 → 7 → 8 |
| **B. Jenkins with Docker agents** | Your CI is Jenkins and agents run Docker | 1 → 2 → 3 → 5 → 7 → 8 |
| **C. Kubernetes** (MCP in the cluster, Jenkins K8s agents or Jobs) | You run Jenkins or workloads on Kubernetes | 1 → 2 → 3 → 6 → 7 → 8 |

How the parts fit together (details in [ARCHITECTURE.md](ARCHITECTURE.md)):

```
CI (Jenkins agent / K8s Job, scanner image)
  devsecops-scan sast|sca|container|dast  ──►  security-reports/<scan_id>/{result.json,result.sarif,policy.json}
  devsecops-scan gate                     ──►  exit 0 pass / 1 policy fail / 2 error  ──► build result
                         │ copy (optional, MCP_REPORTS_DIR)
                         ▼
  shared reports directory / PVC  ──(read-only)──►  MCP server :3000  ◄── MCP clients (Bearer token)
```

The scanners never talk to the MCP server, and the MCP server never runs scans. The only link between them is the reports directory.

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Build and publish the images](#2-build-and-publish-the-images)
3. [Generate secrets](#3-generate-secrets)
4. [Topology A: single host with Docker Compose](#4-topology-a-single-host-with-docker-compose)
5. [Topology B: Jenkins with Docker agents](#5-topology-b-jenkins-with-docker-agents)
6. [Topology C: Kubernetes](#6-topology-c-kubernetes)
7. [Configure the security policy](#7-configure-the-security-policy)
8. [Connect MCP clients](#8-connect-mcp-clients)
9. [Verification checklist](#9-verification-checklist)
10. [Operations](#10-operations)

---

## 1. Prerequisites

### Software

| Component | Version | Needed for |
|---|---|---|
| Docker Engine + Compose v2 | 24+ | Building images; topology A; Jenkins Docker agents |
| Kubernetes + `kubectl` (with Kustomize) | 1.27+ | Topology C |
| Jenkins | 2.4xx LTS | Topologies B and C (optional for C) |
| Node.js | 20+ | Only for local development; the images include their own runtime |

### Resources

| Workload | CPU | Memory | Disk |
|---|---|---|---|
| MCP server | 0.05–0.5 core | 128–512 MiB | none (reads the reports volume) |
| Scanner run | 0.5–2 cores | 1–4 GiB | ~1.3 GB image + ~1 GB Trivy DB cache |
| Reports volume | — | — | about 0.1–5 MB per scan; plan for your retention period |

### Network egress for the scanner

The images already contain the Opengrep rules (pinned commit) and the Nuclei templates (pinned tag). At scan time, only these destinations are needed:

| Destination | Used by | Required? |
|---|---|---|
| `mirror.gcr.io`, `ghcr.io` (Trivy DB, Java DB) | `sca --tool trivy`, `container` | Yes, unless you set `TRIVY_DB_REPOSITORY` / `TRIVY_JAVA_DB_REPOSITORY` to an internal mirror |
| `api.osv.dev` | `sca --tool osv-scanner` (the default SCA tool) | Yes, or use `--tool trivy` |
| Your container registry | `container` scans | Only for container scans |
| The DAST target (staging) | `dast` | Only for DAST |
| `semgrep.dev` | Only if you add `p/...` registry packs to the policy | No (not used by default) |

Opengrep, Katana and Nuclei send no telemetry and do no update checks in this setup. Nuclei runs with `-ni`, so it never calls public interactsh/OAST servers.

### Network egress for building the images

Building the images needs Docker Hub (base images, Trivy, Nuclei), `registry.npmjs.org`, `proxy.golang.org` and `sum.golang.org` (OSV-Scanner, Katana), and `github.com` (Opengrep release, rules and templates). Build once where that access exists, then push to your registry.

---

## 2. Build and publish the images

One `Dockerfile` produces two images:

| Target | Contents | Runs as |
|---|---|---|
| `mcp` (default) | MCP server only (Node 22). No scanners. | uid 1000 (`node`) |
| `scanner` | `devsecops-scan` CLI, Opengrep 1.30.1 + opengrep-rules, OSV-Scanner 2.6.0, Trivy 0.75.0, Nuclei 3.11.1 + nuclei-templates v10.5.0, Katana 1.8.0 | uid 1000 (`node`) |

```bash
git clone https://github.com/nguyentin2068/DevSecOps-MCP.git
cd DevSecOps-MCP

REGISTRY=registry.example.com/security     # change me
VERSION=2.1.0

docker build --target mcp     -t $REGISTRY/devsecops-mcp:$VERSION .
docker build --target scanner -t $REGISTRY/devsecops-scanner:$VERSION .

docker push $REGISTRY/devsecops-mcp:$VERSION
docker push $REGISTRY/devsecops-scanner:$VERSION
```

Check the scanner image:

```bash
docker run --rm $REGISTRY/devsecops-scanner:$VERSION sh -c \
  'id; opengrep --version; trivy --version | head -1; osv-scanner --version | head -1;
   nuclei -version 2>&1 | grep -i version; katana -version 2>&1 | tail -1;
   ls /opt/opengrep-rules /opt/nuclei-templates >/dev/null && echo rules+templates OK'
```

Expected output: `uid=1000(node)`, the five tool versions above, then `rules+templates OK`.

To bump a tool, override its build argument (all of them are listed at the top of the `Dockerfile`). For example:

```bash
docker build --target scanner \
  --build-arg NUCLEI_TEMPLATES_VERSION=v10.5.1 \
  -t $REGISTRY/devsecops-scanner:$VERSION .
```

When you bump Opengrep, also update `OPENGREP_SHA256`. Compute it from the release binary:

```bash
curl -fsSL -o opengrep https://github.com/opengrep/opengrep/releases/download/v1.30.2/opengrep_manylinux_x86
sha256sum opengrep
```

> **Behind a TLS-inspecting proxy?** Add your proxy CA to the build stages (`build`, `tools`), or build on a host with direct egress and push the result.

---

## 3. Generate secrets

Only needed if you run the MCP server. The only secret is the MCP bearer token. It must be at least 32 characters, and the MCP server refuses to start in HTTP mode without one.

```bash
openssl rand -hex 32
```

Store it in your secret manager. Clients need the same value. To rotate it, see [Operations](#10-operations).

---

## 4. Topology A: single host with Docker Compose

### 4.1 Configure

```bash
cp .env.example .env             # optional for scanner-only use
# edit .env:
#   MCP_AUTH_TOKEN=<value from step 3>   # only for the MCP server
#   IMAGE_TAG=2.1.0              # if you pulled published images instead of building locally
mkdir -p security-reports
sudo chown 1000:1000 security-reports   # the scanner writes as uid 1000
```

If your registry images have different names, retag them locally to match `docker-compose.yml`, for example: `docker tag $REGISTRY/devsecops-mcp:2.1.0 devsecops-mcp:2.1.0`.

### 4.2 (Optional) Start the MCP server

The MCP server lives in the Compose profile `mcp`. Skip this step for scanner-only use.

```bash
docker compose --profile mcp up -d mcp   # add --build to build locally instead
docker compose ps                     # mcp should become "healthy"
curl -s http://127.0.0.1:3000/health  # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3000/mcp   # 401
```

The port binds to `127.0.0.1` only. To expose it to other machines, put a TLS reverse proxy in front (see [8.3](#83-exposing-the-mcp-server-over-the-network)).

### 4.3 Run scans

`SCAN_SOURCE` in `.env` selects the source tree mounted read-only at `/workspace/src`. The default is `./test-samples`.

```bash
docker compose build scanner     # or tag a pulled image as devsecops-scanner:$IMAGE_TAG

docker compose run --rm scanner devsecops-scan sast --target /workspace/src
docker compose run --rm scanner devsecops-scan sca  --target /workspace/src             # OSV-Scanner
docker compose run --rm scanner devsecops-scan sca  --target /workspace/src --tool trivy
```

Results appear in `./security-reports/<scan_id>/` (and, if it runs, the MCP server sees them immediately). Without MCP, read them with `docker compose run --rm scanner devsecops-scan report --scan-id <id> --format markdown` or open the `.sarif` files in your IDE.

### 4.4 Try DAST against the demo app

```bash
docker compose --profile demo up -d dast-target
docker compose run --rm scanner devsecops-scan dast --target http://dast-target:3001/ --dast-mode full
```

Expected: Katana crawls a few URLs, Nuclei's fuzzing pass reports reflected XSS and open redirects (`medium`), and the gate fails (exit 1).

This takes 15–20 minutes, mostly for the template pass: about 11,700 templates against a single-threaded demo app. For a quicker look at the fuzzing pass, temporarily set `dast.nuclei.include_tags: [dast, misconfig]` in a copy of the policy and pass it with `--rules`. Stop the demo afterwards with `docker compose --profile demo stop dast-target`.

### 4.5 Scan another project on the same host

Point `SCAN_SOURCE` at the project and run the scans as above, or run the image directly:

```bash
docker run --rm -u 1000:1000 \
  -v /path/to/project:/workspace/src:ro \
  -v $PWD/security-reports:/workspace/security-reports \
  $REGISTRY/devsecops-scanner:$VERSION \
  devsecops-scan sast --target /workspace/src
```

---

## 5. Topology B: Jenkins with Docker agents

### 5.1 Jenkins prerequisites

1. Agents with Docker that can pull `$REGISTRY/devsecops-scanner:$VERSION`. Run `docker login` on the agent, or configure registry credentials in Jenkins.
2. Plugins: **Pipeline**, **Docker Pipeline**, **Timestamper**, **Warnings Next Generation** (publishes SARIF).
3. The scanner needs no Jenkins credentials. Secrets only matter if you scan private container images; then log the agent in to that registry.

### 5.2 Add the pipeline to an application repository

Copy [`Jenkinsfile`](../Jenkinsfile) into the repository you want to scan, or use it as a shared pipeline. Then edit:

- the default of `SCANNER_IMAGE` (two places: `agent.docker.image` and `parameters`) to `$REGISTRY/devsecops-scanner:$VERSION`;
- optionally `SECURITY_RULES_PATH`, to keep the policy in the application repository (see [7](#7-configure-the-security-policy)).

Create the job: **New Item → Pipeline → Pipeline script from SCM** and point it at the repository. The first run registers the parameters.

| Parameter | Meaning |
|---|---|
| `SCANNER_IMAGE` | Scanner image to run the stages in |
| `IMAGE_REF` | Optional container image to scan with Trivy (for example the image this build just pushed) |
| `DAST_TARGET_URL` | Optional staging URL for DAST; must pass the SSRF guard and allowlist |
| `DAST_MODE` | `baseline` (known issues) or `full` (adds Katana + fuzzing; staging only) |

### 5.3 What a run does

1. **Prepare**: computes a unique scan id prefix from the job name and build number.
2. **Pre-check: detect languages**: `devsecops-scan detect` counts the files per language in the checkout, prints the table to the console and stores `security-reports/languages-<prefix>.json`. The languages that have rule sets in `sast.opengrep.language_configs` are kept in `SCAN_LANGUAGES`.
3. **Scans** (parallel): Opengrep (with `--languages "$SCAN_LANGUAGES"`: only the rule sets of the detected languages, plus the common baseline and secrets rules), OSV-Scanner, Trivy fs, plus Trivy image if `IMAGE_REF` is set. Each runs with `--no-fail`, so all of them finish.
4. **DAST** if `DAST_TARGET_URL` is set.
5. **Security gate**: writes `security-reports/summary-<prefix>.md`, then `devsecops-scan gate` fails the build on exit 1 (policy) or 2 (scanner error or missing results).
6. **Post**: archives `security-reports/**`, publishes the SARIF files in Warnings NG, and optionally copies the results to the MCP server (next step).

> OSV-Scanner exits with code 127 when it cannot reach `api.osv.dev`. The stage then fails (exit 2) by design: the gate never passes on missing evidence. Allow that egress, or replace the OSV stage with Trivy.

### 5.4 Deliver results to the MCP server

Jenkins writes results into its workspace. For the MCP server to see them, give the agent a directory that the MCP server also mounts, and set `MCP_REPORTS_DIR`:

1. **On the Docker host that runs the agents**, create the shared directory:

   ```bash
   sudo mkdir -p /srv/devsecops/security-reports
   sudo chown 1000:1000 /srv/devsecops/security-reports
   ```

   If your Jenkins agent user is not uid 1000, make the directory writable by that uid. The MCP server only needs to read it, and files are created world-readable.

2. **In the Jenkinsfile**, mount it into the scanner container:

   ```groovy
   agent {
     docker {
       image(params.SCANNER_IMAGE ?: 'registry.example.com/security/devsecops-scanner:2.1.0')
       args '-v /srv/devsecops/security-reports:/srv/devsecops/security-reports'
     }
   }
   ```

3. **In Jenkins**, go to *Manage Jenkins → System → Global properties → Environment variables* (or set it on the node) and add `MCP_REPORTS_DIR=/srv/devsecops/security-reports`.

4. **Run the MCP server** on that host with the directory mounted read-only. With Compose, change the `mcp` volume in `docker-compose.yml`:

   ```yaml
   volumes:
     - /srv/devsecops/security-reports:/app/security-reports:ro
   ```

After each build, the `post` step copies that build's scan directories into `MCP_REPORTS_DIR`. It copies to a temporary name, then renames, and never overwrites. Without `MCP_REPORTS_DIR`, the step is skipped and results are only archived in Jenkins.

If the agents and the MCP server run on different hosts, use a shared filesystem (NFS, SMB) mounted at the same path on both, or run an `rsync` job after each build.

---

## 6. Topology C: Kubernetes

Without the MCP server, skip 6.1–6.4 (the base only deploys MCP-related objects) and go to [6.5](#65-run-scans-in-the-cluster), using the Jenkins pod template or `scan-job-standalone.yaml` in any namespace.

The Kustomize base in `deploy/k8s/base` deploys the MCP server, the shared `security-reports` PVC and NetworkPolicies into the `devsecops` namespace. That namespace enforces the Pod Security `restricted` standard. Scanners run as Jenkins Kubernetes agents or as Jobs.

### 6.1 Prepare an overlay

Keep your site-specific settings in an overlay instead of editing the base:

```bash
mkdir -p deploy/k8s/overlays/prod
cat > deploy/k8s/overlays/prod/kustomization.yaml <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
images:
  # Match the name the base already sets (registry.example.com/devsecops-mcp).
  - name: registry.example.com/devsecops-mcp
    newName: registry.example.com/security/devsecops-mcp
    newTag: "2.1.0"
patches:
  # Pick a ReadWriteMany storage class (NFS, CephFS, EFS, Azure Files...) and size.
  - target: { kind: PersistentVolumeClaim, name: security-reports }
    patch: |-
      - op: add
        path: /spec/storageClassName
        value: nfs-client
      - op: replace
        path: /spec/resources/requests/storage
        value: 20Gi
EOF
```

If your cluster only has ReadWriteOnce storage, also patch `accessModes` to `ReadWriteOnce` and schedule the scanner pods on the MCP pod's node (`nodeAffinity`). Otherwise the two cannot share the volume.

### 6.2 Create the namespace and the secret

```bash
kubectl create namespace devsecops --dry-run=client -o yaml | kubectl apply -f -
kubectl -n devsecops create secret generic devsecops-secrets \
  --from-literal=mcp-auth-token="$(openssl rand -hex 32)"
```

Prefer your secret manager (External Secrets, Sealed Secrets, Vault). The Deployment only expects a Secret named `devsecops-secrets` with the key `mcp-auth-token`.

### 6.3 Deploy

```bash
kubectl kustomize deploy/k8s/overlays/prod | less        # review
kubectl apply -k deploy/k8s/overlays/prod
kubectl -n devsecops rollout status deploy/mcp
kubectl -n devsecops get pvc security-reports            # must be Bound
```

Smoke test through a port-forward:

```bash
kubectl -n devsecops port-forward svc/mcp 3000:3000 &
curl -s http://127.0.0.1:3000/health                     # {"status":"ok"}
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:3000/mcp   # 401
```

### 6.4 Allow MCP clients in

The `mcp` NetworkPolicy only admits traffic from namespaces labelled `devsecops.io/mcp-client=true`, and the MCP pod has no egress at all.

```bash
kubectl label namespace <client-namespace> devsecops.io/mcp-client=true
# For access from outside the cluster, label the ingress controller's namespace instead:
kubectl label namespace ingress-nginx devsecops.io/mcp-client=true
```

For an Ingress example, see [8.3](#83-exposing-the-mcp-server-over-the-network).

### 6.5 Run scans in the cluster

**Option 1: Jenkins Kubernetes agents.**

1. In the Jenkinsfile, replace the `agent { docker { ... } }` block with:

   ```groovy
   agent { kubernetes { yamlFile 'deploy/k8s/jenkins/scanner-pod.yaml'; defaultContainer 'scanner' } }
   ```

2. Copy `deploy/k8s/jenkins/scanner-pod.yaml` into the application repository and set its image to `$REGISTRY/devsecops-scanner:$VERSION`.

3. To publish results to the MCP server:
   - Configure the Jenkins Kubernetes cloud to start agent pods in the `devsecops` namespace (the PVC lives there).
   - Uncomment the `mcp-reports` volume and volume mount in the pod template.
   - Set `MCP_REPORTS_DIR=/mcp-reports` (as a Jenkins global variable or in the Jenkinsfile `environment`).

   The pod template is compatible with the namespace's `restricted` Pod Security standard.

**Option 2: on-demand Jobs (no Jenkins).**

Without MCP, use `deploy/k8s/examples/scan-job-standalone.yaml`. It needs no PVC and works in any namespace; it prints the markdown report to the logs, and the Job status is the gate result:

```bash
kubectl -n <namespace> create -f deploy/k8s/examples/scan-job-standalone.yaml
kubectl -n <namespace> logs -f job/<generated-name> -c scanner
```

With MCP, edit `REPO_URL`, `REPO_REF` and the image in `deploy/k8s/examples/scan-job.yaml`, then:

```bash
kubectl -n devsecops create -f deploy/k8s/examples/scan-job.yaml
kubectl -n devsecops logs -f job/<generated-name> -c scanner
```

The Job clones the repository, runs Trivy and Opengrep, runs the gate, and writes results to the shared PVC. The Job's status reflects the gate result. For private repositories, mount a deploy key or token Secret into the `clone` init container.

### 6.6 Restrict scanner egress (recommended)

Scanner pods carry the label `devsecops.io/scanner=true`. In the namespace where they run, allow only what they need: DNS, the Trivy DB registries or your mirror, `api.osv.dev`, your container registry, and your staging CIDRs for DAST. This limits the damage from a malicious template, rule or target.

---

## 7. Configure the security policy

The policy is [`src/config/security-rules.yml`](../src/config/security-rules.yml). The scanner image ships it at `/app/src/config/security-rules.yml`. To customise it per application:

1. Copy it into the application repository, for example as `.devsecops/security-rules.yml`.
2. Point the scanner at it: `SECURITY_RULES_PATH=$WORKSPACE/.devsecops/security-rules.yml` (the Jenkinsfile has this line commented out), or pass `--rules <file>`.
3. Relative rule paths in the file resolve against the file's own directory. `${OPENGREP_RULES_DIR}` and `${NUCLEI_TEMPLATES_DIR}` come from the image. If the copied file still references `opengrep/baseline.yml`, either copy that file next to it or change the entry to `/app/src/config/opengrep/baseline.yml`.

The file is validated strictly: unknown keys and invalid values fail with exit code 2 and a clear message. Validate changes before committing:

```bash
docker run --rm -v $PWD/.devsecops:/rules:ro $REGISTRY/devsecops-scanner:$VERSION \
  devsecops-scan gate --rules /rules/security-rules.yml --scan-id does-not-exist
# A valid file gets as far as "Scan not found"; an invalid one reports the exact key.
```

### Decisions to make before go-live

| Setting | Default | Recommendation |
|---|---|---|
| `global_policy.enforcement_level` | `strict` | Start with `permissive` for one or two weeks to see the results without failing builds, then switch to `strict`. |
| `sast.thresholds` | critical/high 0; medium/low not gated | Keep. After triage, set `medium` to a number. Suppress reviewed false positives inline: `// nosemgrep: <rule-id>` with a reason. |
| `sast.opengrep.configs` | baseline + secrets | Rules that always run. Add your own rule files here. |
| `sast.opengrep.language_configs` | one entry per language in opengrep-rules | Only the detected languages run. Remove a language to stop scanning it; point an entry at your own rules to replace the defaults. |
| `sca.thresholds` | critical/high 0; medium 3; low 10 | Adjust to your patching SLA. |
| `container.trivy.ignore_unfixed` | `true` | Keep, so the gate only fails on findings you can fix. |
| `dast.thresholds` | critical/high/medium 0 | Keep. Reflected XSS and open redirect are `medium`. |
| `dast.target_policy` | empty (private networks allowed, loopback/metadata blocked) | Set `allowed_hosts` / `allowed_cidrs` to your staging environments. Once set, nothing else can be scanned. |
| `dast.mode` | `baseline` | Use `full` only against environments where active attacks are acceptable. |
| `dast.nuclei.include_tags` / `severities` | all templates | The full template set takes 15–20 minutes on a slow target. For CI, consider `include_tags: [cve, misconfig, exposure, default-login]`. |

---

## 8. Connect MCP clients

The MCP server exposes five read-only tools: `list_scans`, `get_scan_result`, `summarize_findings`, `validate_security_policy` and `generate_security_report`. It cannot start scans.

### 8.1 Claude Code (HTTP)

```bash
claude mcp add --transport http devsecops https://mcp.devsecops.example.com/mcp \
  --header "Authorization: Bearer $MCP_AUTH_TOKEN"
```

For a local Compose deployment, use `http://127.0.0.1:3000/mcp`.

### 8.2 Any client (raw JSON-RPC check)

```bash
curl -s -X POST http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer $MCP_AUTH_TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_scans","arguments":{"limit":5}}}'
```

The response lists the most recent scans and their severity summaries.

### 8.3 Exposing the MCP server over the network

Always terminate TLS in front of the MCP server; the bearer token must not travel in clear text. Kubernetes example (NGINX Ingress + cert-manager):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: mcp
  namespace: devsecops
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    nginx.ingress.kubernetes.io/limit-rps: "10"          # the app has no rate limiting of its own
spec:
  ingressClassName: nginx
  tls:
    - hosts: [mcp.devsecops.example.com]
      secretName: mcp-tls
  rules:
    - host: mcp.devsecops.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: mcp, port: { number: 3000 } } }
```

Then set `MCP_ALLOWED_HOSTS=mcp.devsecops.example.com` on the Deployment (DNS-rebinding protection), and label the ingress controller's namespace as in [6.4](#64-allow-mcp-clients-in).

---

## 9. Verification checklist

Run through this after the first deployment and after every upgrade.

- [ ] `docker run --rm <scanner> sh -c 'opengrep --version; trivy --version; nuclei -version'` prints the expected versions ([2](#2-build-and-publish-the-images)).
- [ ] `GET /health` returns `{"status":"ok"}`; `POST /mcp` without a token returns `401`.
- [ ] A SAST scan of a deliberately vulnerable sample fails the gate (exit 1); a clean directory passes (exit 0).
- [ ] An SCA scan downloads the Trivy DB (or uses your mirror) and completes. An OSV scan completes, which proves `api.osv.dev` is reachable.
- [ ] `devsecops-scan dast --target http://169.254.169.254/` is refused (SSRF guard). Your staging URL is accepted.
- [ ] After a Jenkins build, the scan directories appear in the MCP reports directory, and `list_scans` shows them.
- [ ] The Jenkins build page shows the SARIF findings (Warnings NG) and the archived `summary-*.md`.
- [ ] Kubernetes: `kubectl -n devsecops get pods` shows `mcp` Running, no Pod Security warnings, and the PVC Bound.

---

## 10. Operations

### Rotate the MCP token

Update the secret (`.env` and `docker compose --profile mcp up -d mcp`, or the Kubernetes Secret followed by `kubectl -n devsecops rollout restart deploy/mcp`), then give clients the new value. The old token stops working on restart.

### Upgrade

1. Bump the build arguments (tools, templates, rules) and rebuild both images with a new tag ([2](#2-build-and-publish-the-images)).
2. Read the release notes of opengrep-rules / nuclei-templates: new rules and templates can change results.
3. Roll out the scanner first: change `SCANNER_IMAGE`, then run a pipeline on a known project and compare findings with the previous build.
4. Then roll out the MCP image (`IMAGE_TAG` or the overlay's `newTag`).

### Retention and backup

Scan results are never deleted automatically. Example of a 90-day retention job on the host or in a CronJob:

```bash
find /srv/devsecops/security-reports -mindepth 1 -maxdepth 1 -type d -mtime +90 -exec rm -rf {} +
```

Back up the reports directory or PVC if you need the audit trail. The Jenkins archive also keeps each build's results.

### Logs and monitoring

- Both images log JSON to stderr: use `docker logs` or `kubectl logs`. Set `LOG_LEVEL=debug` for troubleshooting.
- Monitor `GET /health` on the MCP server.
- Rejected MCP requests are logged as `Rejected MCP request without a valid bearer token`. Alert on bursts of them.

### Troubleshooting

See the troubleshooting table in the [README](../README.md#troubleshooting). Common setup issues:

| Symptom | Cause / fix |
|---|---|
| Scanner `EACCES` writing reports | The reports directory is not writable by the scanner's uid (1000, or the Jenkins agent uid): `chown` it. |
| `Rules file references ${OPENGREP_RULES_DIR}, which is not set` | You are running the CLI outside the scanner image. Use the image, or set the variable to an opengrep-rules checkout. |
| `osv-scanner exited with code 127` | No egress to `api.osv.dev`. |
| Trivy DB download fails | No egress to `mirror.gcr.io`/`ghcr.io`. Set `TRIVY_DB_REPOSITORY` (and `TRIVY_JAVA_DB_REPOSITORY`) to an internal mirror. |
| MCP `list_scans` is empty after Jenkins builds | `MCP_REPORTS_DIR` is not set, not mounted on the agent, or not the directory the MCP server mounts ([5.4](#54-deliver-results-to-the-mcp-server)). |
| Pod stuck `Pending` with the reports PVC | The storage class does not support ReadWriteMany, or the agent pod is in another namespace ([6.5](#65-run-scans-in-the-cluster)). |
| DAST target `blocked address` | The target resolves to loopback or link-local. Use its real name, or allowlist it in `dast.target_policy`. |
