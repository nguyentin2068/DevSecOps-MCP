# Hướng dẫn dựng Jenkins để chạy pipeline DevSecOps

Tài liệu này hướng dẫn dựng một Jenkins chạy bằng Docker trên một máy (Linux, hoặc Windows qua WSL2), rồi chạy [`Jenkinsfile`](../Jenkinsfile) của project: pre-check nhận diện ngôn ngữ → Opengrep, OSV-Scanner, Trivy song song → DAST (tuỳ chọn) → security gate → publish SARIF.

Đây là cấu hình **lab / một máy**: Jenkins controller tự chạy các stage và dùng Docker daemon của máy. Khi đưa vào production, xem [Đưa lên production](#9-đưa-lên-production) và [deployment guide §5](DEPLOYMENT-GUIDE.md#5-topology-b-jenkins-with-docker-agents).

## Mục lục

1. [Kiến trúc](#1-kiến-trúc)
2. [Chuẩn bị](#2-chuẩn-bị)
3. [Build image Jenkins có sẵn Docker CLI và plugin](#3-build-image-jenkins-có-sẵn-docker-cli-và-plugin)
4. [Chạy Jenkins](#4-chạy-jenkins)
5. [Cấu hình lần đầu](#5-cấu-hình-lần-đầu)
6. [Tạo job pipeline và chạy build đầu tiên](#6-tạo-job-pipeline-và-chạy-build-đầu-tiên)
7. [Đọc kết quả](#7-đọc-kết-quả)
8. [Tuỳ chọn: DAST, scan image, gửi kết quả cho MCP server](#8-tuỳ-chọn-dast-scan-image-gửi-kết-quả-cho-mcp-server)
9. [Đưa lên production](#9-đưa-lên-production)
10. [Xử lý sự cố](#10-xử-lý-sự-cố)

---

## 1. Kiến trúc

```
Trình duyệt ──► http://localhost:8080
                    │
        ┌───────────▼────────────┐        /var/run/docker.sock
        │  container "jenkins"   │ ─────────────────────────────► Docker daemon
        │  (Jenkins + docker CLI)│                                    │
        └───────────┬────────────┘                                    │ docker run (agent { docker { ... } })
                    │ /var/jenkins_home (cùng đường dẫn trên host)     ▼
                    │                                   container scanner devsecops-scanner
                    └──────────── workspace ──────────► devsecops-scan detect / sast / sca / gate
                                                         │
                                                         ▼
                                     workspace/security-reports/<scan_id>/ → archive + SARIF
```

- Jenkinsfile dùng `agent { docker { image ... } }`: mỗi build, Jenkins chạy một container từ **image scanner** và thực thi các stage trong đó. Vì vậy Jenkins cần Docker CLI và quyền truy cập Docker daemon.
- `jenkins_home` được mount ở **cùng một đường dẫn** (`/var/jenkins_home`) trên host và trong container Jenkins. Khi Jenkins bảo Docker mount workspace vào container scanner, đường dẫn đó tồn tại thật trên host.
- Image Jenkins chính thức chạy với user `jenkins` uid 1000, trùng uid của image scanner, nên container scanner ghi được vào workspace mà không cần chỉnh quyền.

## 2. Chuẩn bị

| Yêu cầu | Ghi chú |
|---|---|
| Docker Engine + Compose v2 (Linux) hoặc Docker Desktop với WSL 2 engine (Windows) | Trên Windows, làm mọi bước trong terminal Ubuntu của WSL2, xem [deployment guide §4.6](DEPLOYMENT-GUIDE.md#46-windows-workstation-wsl2) |
| Repo này đã clone và image scanner đã build | `docker compose build scanner` → image `devsecops-scanner:local` |
| RAM | Jenkins ~1 GB, một lượt scan 1–4 GB. Trên WSL2 nên cấp ≥ 6 GB qua `.wslconfig` |
| Mạng ra ngoài | Tải plugin Jenkins; Trivy DB (`mirror.gcr.io`/`ghcr.io`); `api.osv.dev` cho OSV-Scanner; GitHub nếu checkout repo từ đó |

Kiểm tra image scanner:

```bash
cd ~/DevSecOps-MCP
docker compose build scanner
docker image ls devsecops-scanner        # phải có tag "local"
```

## 3. Build image Jenkins có sẵn Docker CLI và plugin

Tạo thư mục riêng cho Jenkins, ngoài repo:

```bash
mkdir -p ~/jenkins-devsecops && cd ~/jenkins-devsecops
```

Tạo file `Dockerfile`:

```dockerfile
FROM jenkins/jenkins:lts-jdk21

# Docker CLI only (the daemon is the host's, reached through the mounted socket)
COPY --from=docker:27-cli /usr/local/bin/docker /usr/local/bin/docker

# Plugins the Jenkinsfile needs, plus Git (checkout) and Stage View (stage table)
RUN jenkins-plugin-cli --plugins \
    workflow-aggregator \
    docker-workflow \
    timestamper \
    warnings-ng \
    git \
    pipeline-stage-view
```

| Plugin | Dùng cho |
|---|---|
| `workflow-aggregator` (Pipeline) | Chạy Jenkinsfile dạng declarative |
| `docker-workflow` (Docker Pipeline) | `agent { docker { ... } }` |
| `timestamper` | `options { timestamps() }` |
| `warnings-ng` (Warnings Next Generation) | `recordIssues(... sarif(...))`: hiển thị finding từ file SARIF |
| `git` | Checkout repo |
| `pipeline-stage-view` | Bảng stage trên trang job (không bắt buộc) |

Build:

```bash
docker build -t jenkins-devsecops:lts .
```

## 4. Chạy Jenkins

Tạo `jenkins_home` trên host, đúng đường dẫn sẽ dùng trong container, thuộc uid 1000:

```bash
sudo mkdir -p /var/jenkins_home
sudo chown 1000:1000 /var/jenkins_home
```

Chạy container:

```bash
docker run -d --name jenkins --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v /var/jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  jenkins-devsecops:lts
```

- `-p 127.0.0.1:8080:8080`: chỉ mở Jenkins cho máy này. Trên Windows vẫn mở được `http://localhost:8080` từ trình duyệt.
- `-v /var/run/docker.sock:...`: Jenkins điều khiển Docker daemon của máy. **Quyền này tương đương root trên host**, chỉ dùng cho lab (xem [§9](#9-đưa-lên-production)).

Kiểm tra user `jenkins` trong container gọi được Docker:

```bash
docker exec jenkins docker version
```

Nếu báo `permission denied while trying to connect to the Docker daemon socket`, thêm group sở hữu socket cho container rồi tạo lại container (dữ liệu nằm trong `/var/jenkins_home`, không mất):

```bash
SOCK_GID=$(docker exec jenkins stat -c %g /var/run/docker.sock)
docker rm -f jenkins
docker run -d --name jenkins --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -v /var/jenkins_home:/var/jenkins_home \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$SOCK_GID" \
  jenkins-devsecops:lts
docker exec jenkins docker version
```

Nếu vẫn lỗi vì socket không cho group ghi (`docker exec jenkins ls -l /var/run/docker.sock` không có `rw` ở nhóm, hay gặp với Docker Desktop), thì **chỉ trong lab** có thể mở quyền: `docker exec -u root jenkins chmod 666 /var/run/docker.sock`. Lệnh này cần chạy lại mỗi khi Docker Desktop khởi động lại.

## 5. Cấu hình lần đầu

1. Lấy mật khẩu admin ban đầu:
   ```bash
   docker exec jenkins cat /var/jenkins_home/secrets/initialAdminPassword
   ```
2. Mở `http://localhost:8080`, dán mật khẩu.
3. Chọn **Install suggested plugins** (các plugin cần cho pipeline đã có sẵn trong image), rồi tạo tài khoản admin.
4. **Manage Jenkins → Plugins → Installed plugins**: kiểm tra có *Docker Pipeline*, *Warnings*, *Timestamper*.
5. Tuỳ chọn: **Manage Jenkins → Nodes → Built-In Node → Configure**, số executor để `2` (mặc định). Pipeline chạy 3–4 scanner song song nhưng trong cùng **một** container agent, nên 1 build chỉ chiếm 1 executor.

## 6. Tạo job pipeline và chạy build đầu tiên

### 6.1 Cho Jenkins dùng image scanner đã build

Jenkinsfile mặc định dùng image `registry.example.com/devsecops-scanner:2.1.0`. Ở build đầu tiên, các tham số chưa được đăng ký nên Jenkins sẽ dùng giá trị mặc định này. Trong lab chưa có registry, gắn thêm tên đó cho image vừa build; Docker dùng image có sẵn ở máy, không pull:

```bash
docker tag devsecops-scanner:local registry.example.com/devsecops-scanner:2.1.0
```

Từ build thứ hai, có thể chọn image khác bằng tham số `SCANNER_IMAGE` (ví dụ `devsecops-scanner:local`) trong **Build with Parameters**. Sau mỗi lần build lại image scanner, nhớ chạy lại lệnh `docker tag` nếu vẫn dùng tên mặc định.

### 6.2 Tạo job

1. **New Item** → đặt tên, ví dụ `devsecops-demo` → chọn **Pipeline** → OK.
2. Mục **Pipeline**:
   - *Definition*: **Pipeline script from SCM**
   - *SCM*: **Git**
   - *Repository URL*: URL của repo cần scan. Để thử ngay, dùng chính repo này (ví dụ `https://github.com/nguyentin2068/DevSecOps-MCP.git`). Thư mục `test-samples/` chứa code và thư viện có lỗ hổng, nên gate sẽ **FAIL** (đúng như mong đợi).
   - *Credentials*: bỏ trống nếu repo public. Nếu repo private: **Add → Jenkins → Username with password**, username GitHub, password là Personal Access Token (quyền đọc repo).
   - *Branch Specifier*: `*/main`
   - *Script Path*: `Jenkinsfile`
3. **Save** → **Build Now**.

Muốn scan repo ứng dụng khác: copy `Jenkinsfile` vào repo đó (hoặc trỏ *Script Path* tới bản copy) và tạo job trỏ tới repo ứng dụng. Policy mặc định nằm sẵn trong image scanner. Nếu muốn giữ policy trong repo ứng dụng, xem `SECURITY_RULES_PATH` trong Jenkinsfile.

### 6.3 Những gì build chạy

| Stage | Việc làm | Ghi chú |
|---|---|---|
| Prepare | Tạo tiền tố scan id từ tên job + số build; tạo `HOME`, `security-reports`, cache Trivy | |
| Pre-check: detect languages | `devsecops-scan detect`: in bảng ngôn ngữ ra console, lưu `security-reports/languages-<prefix>.json`, đặt `SCAN_LANGUAGES` | |
| Scans (song song) | Opengrep (`--languages "$SCAN_LANGUAGES"`), OSV-Scanner, Trivy fs; Trivy image nếu có `IMAGE_REF` | Mỗi scanner chạy với `--no-fail` để tất cả đều chạy xong |
| DAST: Katana + Nuclei | Chỉ chạy khi có `DAST_TARGET_URL` | |
| Security gate | Ghi `summary-<prefix>.md`, rồi `devsecops-scan gate` quyết định PASS/FAIL | Exit 1 = vi phạm policy, 2 = lỗi scanner/thiếu kết quả → build FAILURE |
| post | Archive `security-reports/**`, publish SARIF bằng Warnings NG, copy kết quả cho MCP nếu có `MCP_REPORTS_DIR` | Luôn chạy, kể cả khi gate fail |

Build đầu tiên lâu hơn vì Trivy phải tải vulnerability DB (vài trăm MB). Cache nằm trong `<workspace>@tmp/trivy-cache` và được giữ cho các build sau trên cùng máy.

## 7. Đọc kết quả

- **Console Output**: mỗi dòng log của scanner có tiền tố tên tool (`[opengrep]`, `[trivy]`, `[osv-scanner]`, ...), kèm câu lệnh chạy và exit code. Stage pre-check in bảng ngôn ngữ tìm thấy. Stage gate in `Policy: PASS/FAIL` cùng lý do.
- **DevSecOps scans** (link bên trái trang build, do Warnings NG tạo): danh sách finding, lọc theo mức độ, file, rule. Finding SAST mang rule ID dạng `sast-<ngôn ngữ>-<NNNN>`.
- **Build Artifacts**: `security-reports/<scan_id>/result.json`, `result.sarif`, `policy.json`, `languages-<prefix>.json` và báo cáo tổng hợp `summary-<prefix>.md`.

Trạng thái build:

| Kết quả | Ý nghĩa |
|---|---|
| SUCCESS | Gate PASS (hoặc WARN khi `enforcement_level: permissive`) |
| FAILURE ở stage *Security gate* | Có finding vượt ngưỡng trong `security-rules.yml`. Xem summary/Warnings NG |
| FAILURE ở một stage scan | Scanner lỗi (exit 2). Xem log `[tool]` của stage đó |

## 8. Tuỳ chọn: DAST, scan image, gửi kết quả cho MCP server

### 8.1 DAST với app demo

Chạy app demo có lỗ hổng trên mạng bridge mặc định của Docker. Container agent của Jenkins cũng nằm trên mạng này nên gọi được app qua IP:

```bash
cd ~/DevSecOps-MCP
docker compose --profile demo build dast-target          # image devsecops-mcp:local
docker run -d --name dast-demo --read-only --cap-drop ALL --security-opt no-new-privileges \
  -e HOST=0.0.0.0 -e PORT=3001 -e NODE_PATH=/app/node_modules \
  -v "$PWD/test-samples:/samples:ro" \
  devsecops-mcp:local node /samples/vulnerable-server.js
docker inspect -f '{{.NetworkSettings.IPAddress}}' dast-demo   # ví dụ 172.17.0.3
```

**Build with Parameters**: `DAST_TARGET_URL=http://172.17.0.3:3001/`, `DAST_MODE=baseline` (nhanh hơn) hoặc `full` (thêm crawl + fuzzing, 15–20 phút với app demo). Địa chỉ private được SSRF guard cho phép khi `dast.target_policy` trống. Khi đã đặt allowlist, phải thêm dải đó vào `allowed_cidrs`. Chạy xong thì dừng app: `docker rm -f dast-demo`.

Với môi trường thật, trỏ `DAST_TARGET_URL` tới staging và giới hạn bằng `dast.target_policy.allowed_hosts`/`allowed_cidrs`. **Không chạy `full` vào production.**

### 8.2 Scan một container image

Đặt `IMAGE_REF`, ví dụ `nginx:1.27` hoặc image ứng dụng vừa build. Stage *Container: Trivy image* sẽ chạy. Image private cần `docker login` trên máy chạy Docker.

### 8.3 Gửi kết quả cho MCP server

Để MCP server (AI triage) thấy kết quả của từng build:

1. Dùng thư mục mà MCP server trong Compose đang mount, ví dụ `~/DevSecOps-MCP/security-reports` (thuộc uid 1000).
2. Trong Jenkinsfile của repo được scan, thêm `args` cho agent để mount thư mục đó vào container scanner (dùng đường dẫn tuyệt đối trên host):
   ```groovy
   agent {
     docker {
       image(params.SCANNER_IMAGE ?: 'registry.example.com/devsecops-scanner:2.1.0')
       args '-v /home/<user>/DevSecOps-MCP/security-reports:/mcp-reports'
     }
   }
   ```
3. **Manage Jenkins → System → Global properties → Environment variables**: thêm `MCP_REPORTS_DIR` = `/mcp-reports`.
4. Chạy MCP server: `docker compose --profile mcp up -d mcp` (xem README).

Sau mỗi build, bước `post` copy các thư mục scan của build đó sang `MCP_REPORTS_DIR`: copy vào tên tạm rồi đổi tên, không ghi đè. MCP tool `list_scans` sẽ thấy chúng ngay.

## 9. Đưa lên production

Cấu hình lab ở trên đánh đổi bảo mật lấy sự đơn giản. Khi dùng thật:

- **Không chạy build trên controller và không mount `docker.sock` vào controller.** Dùng agent riêng có Docker (SSH/inbound agent), đặt executor của Built-In Node về `0`, hoặc dùng Kubernetes agent với pod template [`deploy/k8s/jenkins/scanner-pod.yaml`](../deploy/k8s/jenkins/scanner-pod.yaml) (xem chú thích ở khối `agent` trong Jenkinsfile).
- **Đẩy image scanner lên registry nội bộ** và đổi giá trị mặc định `SCANNER_IMAGE` (2 chỗ trong Jenkinsfile) thành image đó, thay cho việc `docker tag`.
- **Đặt Jenkins sau reverse proxy có TLS**, bật xác thực/SSO, phân quyền theo job.
- **Giới hạn mạng ra ngoài của agent scanner**: chỉ những endpoint cần (Trivy DB mirror, `api.osv.dev`, staging cho DAST). Có thể dùng mirror nội bộ cho Trivy (`TRIVY_DB_REPOSITORY`).
- **Review thay đổi `security-rules.yml` như review code**, vì nó quyết định build pass hay fail.

Chi tiết: [deployment guide §5–§7](DEPLOYMENT-GUIDE.md#5-topology-b-jenkins-with-docker-agents).

## 10. Xử lý sự cố

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| `docker: not found` trong stage | Image Jenkins chưa có Docker CLI. Build lại theo [§3](#3-build-image-jenkins-có-sẵn-docker-cli-và-plugin) |
| `permission denied ... docker.sock` | User `jenkins` không có quyền với socket. Xem [§4](#4-chạy-jenkins) (`--group-add`) |
| `pull access denied for registry.example.com/devsecops-scanner` | Chưa gắn tên mặc định cho image local ([§6.1](#61-cho-jenkins-dùng-image-scanner-đã-build)), hoặc `SCANNER_IMAGE` sai |
| `devsecops-scan: not found` | `SCANNER_IMAGE` đang trỏ tới image MCP (`devsecops-mcp`) thay vì image scanner |
| `Target path is outside the allowed workspace`, hoặc scan ra 0 file | Workspace không được mount đúng vào container scanner: `jenkins_home` phải nằm ở **cùng đường dẫn** trên host và trong container (`-v /var/jenkins_home:/var/jenkins_home`) |
| `EACCES` khi ghi `security-reports` | User Jenkins không phải uid 1000. Dùng image Jenkins chính thức, hoặc `chown` thư mục cho đúng uid |
| `No such DSL method 'recordIssues'` | Thiếu plugin Warnings Next Generation |
| `No such DSL method 'timestamps'` | Thiếu plugin Timestamper |
| `osv-scanner exited with code 127 ... api.osv.dev` | Máy không ra được `api.osv.dev`. Mở egress, hoặc bỏ stage OSV và dùng Trivy |
| Trivy treo lâu ở lần đầu | Đang tải DB. Xem log `[trivy]`; cần egress tới `mirror.gcr.io` hoặc `ghcr.io` |
| `blocked address` khi chạy DAST | URL trỏ tới loopback/metadata, hoặc nằm ngoài allowlist. Dùng IP/hostname thật của staging ([§8.1](#81-dast-với-app-demo)) |
| Tham số build không xuất hiện | Bình thường ở build đầu: Jenkins đăng ký tham số sau lần chạy đầu tiên của Jenkinsfile |
| Build FAILURE ở *Security gate* với repo demo | Đúng như mong đợi: `test-samples/` cố ý chứa lỗ hổng |
