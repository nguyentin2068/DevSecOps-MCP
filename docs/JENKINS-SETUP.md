# Hướng dẫn dựng Jenkins để chạy pipeline DevSecOps

Tài liệu này hướng dẫn dựng một Jenkins chạy bằng Docker trên một máy (Linux, hoặc Windows qua WSL2), rồi chạy [`Jenkinsfile`](../Jenkinsfile) của project. Pipeline có **9 stage chính**; stage *Scans* chứa thêm 4 stage con chạy song song, nên tổng cộng là **13 stage** (xem [§6.3](#63-các-stage-của-pipeline)):

```
Prepare → Pre-check → Scans (Opengrep ∥ OSV-Scanner ∥ Trivy fs ∥ Trivy image) → DAST
        → Correlate → DefectDojo import → AI triage → Rule stats → Security gate → post
```

Đây là cấu hình **lab / một máy**: Jenkins controller tự chạy các stage và dùng Docker daemon của máy. Khi đưa vào production, xem [Đưa lên production](#9-đưa-lên-production) và [deployment guide §5](DEPLOYMENT-GUIDE.md#5-topology-b-jenkins-with-docker-agents).

## Mục lục

1. [Kiến trúc](#1-kiến-trúc)
2. [Chuẩn bị](#2-chuẩn-bị)
3. [Build image Jenkins có sẵn Docker CLI và plugin](#3-build-image-jenkins-có-sẵn-docker-cli-và-plugin)
4. [Chạy Jenkins](#4-chạy-jenkins)
5. [Cấu hình lần đầu](#5-cấu-hình-lần-đầu)
6. [Tạo job pipeline và chạy build đầu tiên](#6-tạo-job-pipeline-và-chạy-build-đầu-tiên)
7. [Đọc kết quả](#7-đọc-kết-quả)
8. [Bật các stage tuỳ chọn: DAST, scan image, MCP, DefectDojo, AI triage, thống kê rule](#8-bật-các-stage-tuỳ-chọn-dast-scan-image-mcp-defectdojo-ai-triage-thống-kê-rule)
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
                    └──────────── workspace ──────────► devsecops-scan detect / sast / sca / dast
                                                         │   correlate / defectdojo / triage / rule-stats / gate
                                                         ▼
                                     workspace/security-reports/ → archive + SARIF
                                                         │
                         (tuỳ chọn) DefectDojo ◄─────────┤  reimport finding, đọc quyết định của người review
                         (tuỳ chọn) Claude API ◄─────────┘  AI triage finding chưa ai quyết định
```

- Jenkinsfile dùng `agent { docker { image ... } }`: mỗi build, Jenkins chạy một container từ **image scanner** và thực thi các stage trong đó. Vì vậy Jenkins cần Docker CLI và quyền truy cập Docker daemon.
- `jenkins_home` được mount ở **cùng một đường dẫn** (`/var/jenkins_home`) trên host và trong container Jenkins. Khi Jenkins bảo Docker mount workspace vào container scanner, đường dẫn đó tồn tại thật trên host.
- Image Jenkins chính thức chạy với user `jenkins` uid 1000, trùng uid của image scanner, nên container scanner ghi được vào workspace mà không cần chỉnh quyền.
- DefectDojo và Claude API là **tuỳ chọn**: không cấu hình thì các stage liên quan bị bỏ qua. Mọi lệnh đều chạy trong container scanner, nên container đó phải gọi được tới chúng.

## 2. Chuẩn bị

| Yêu cầu | Ghi chú |
|---|---|
| Docker Engine + Compose v2 (Linux) hoặc Docker Desktop với WSL 2 engine (Windows) | Trên Windows, làm mọi bước trong terminal Ubuntu của WSL2, xem [deployment guide §4.6](DEPLOYMENT-GUIDE.md#46-windows-workstation-wsl2) |
| Repo này đã clone và image scanner đã build | `docker compose build scanner` → image `devsecops-scanner:local` |
| RAM | Jenkins ~1 GB, một lượt scan 1–4 GB. Trên WSL2 nên cấp ≥ 6 GB qua `.wslconfig` |
| Mạng ra ngoài | Tải plugin Jenkins; Trivy DB (`mirror.gcr.io`/`ghcr.io`); `api.osv.dev` cho OSV-Scanner; GitHub nếu checkout repo từ đó. Thêm `api.anthropic.com` nếu bật AI triage, và địa chỉ DefectDojo nếu dùng DefectDojo |

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
    credentials-binding \
    pipeline-stage-view
```

| Plugin | Dùng cho |
|---|---|
| `workflow-aggregator` (Pipeline) | Chạy Jenkinsfile dạng declarative |
| `docker-workflow` (Docker Pipeline) | `agent { docker { ... } }` |
| `timestamper` | `options { timestamps() }` |
| `warnings-ng` (Warnings Next Generation) | `recordIssues(... sarif(...))`: hiển thị finding từ file SARIF |
| `git` | Checkout repo |
| `credentials-binding` | `withCredentials(...)`: đưa API key Anthropic/DefectDojo vào stage AI triage và DefectDojo |
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

### 6.3 Các stage của pipeline

Pipeline có **9 stage chính**. Stage *Scans* chứa 4 stage con chạy song song, nên tổng cộng là **13 stage**:

| # | Stage | Khi nào chạy | Việc làm | Kết quả ghi ra (`security-reports/`) |
|---|---|---|---|---|
| 1 | **Prepare** | Luôn chạy | Tạo tiền tố scan id từ tên job và số build, danh sách scan của build, thông tin DefectDojo (product, engagement `CI/CD <branch>`); tạo `HOME`, `security-reports`, cache Trivy | |
| 2 | **Pre-check: detect languages** | Luôn chạy | `devsecops-scan detect`: in bảng ngôn ngữ ra console, đặt `SCAN_LANGUAGES` | `languages-<prefix>.json` |
| 3 | **Scans** (song song) | Luôn chạy | Chạy 4 stage con 3.1–3.4. Mỗi scanner chạy với `--no-fail` để tất cả đều chạy xong; gate ở stage 9 mới quyết định | |
| 3.1 | ├ SAST: Opengrep | Luôn chạy | Chỉ nạp rule của các ngôn ngữ ở stage 2 (`--languages`), cộng rule chung (baseline, secrets) | `sast-opengrep-<prefix>/` |
| 3.2 | ├ SCA: OSV-Scanner | Luôn chạy | Lỗ hổng thư viện qua `api.osv.dev` | `sca-osv-scanner-<prefix>/` |
| 3.3 | ├ SCA: Trivy fs | Luôn chạy | Lỗ hổng thư viện, secret, cấu hình sai | `sca-trivy-<prefix>/` |
| 3.4 | └ Container: Trivy image | Tham số `IMAGE_REF` có giá trị | Scan container image ([§8.2](#82-scan-một-container-image)) | `container-trivy-<prefix>/` |
| 4 | **DAST: Katana + Nuclei** | Tham số `DAST_TARGET_URL` có giá trị | Scan ứng dụng đang chạy, chế độ `DAST_MODE` ([§8.1](#81-dast-với-app-demo)) | `dast-nuclei-<prefix>/` |
| 5 | **Correlate** | Luôn chạy | `devsecops-scan correlate`: gộp finding trùng giữa các rule và tool (cùng CVE, cùng file:dòng:CWE, cùng endpoint). Không gọi AI, không cần mạng | `triage-<prefix>.json`, `.md` |
| 6 | **DefectDojo import** | Biến `DEFECTDOJO_URL` và `DEFECTDOJO_CREDENTIALS_ID` có giá trị | Reimport từng tool thành một test, giữ mọi finding kể cả Duplicate/FP, gắn tag `corr-*` ([§8.4](#84-đẩy-finding-lên-defectdojo)) | `defectdojo-<prefix>.json` |
| 7 | **AI triage** | Biến `ANTHROPIC_CREDENTIALS_ID` có giá trị | Claude đánh giá các finding **chưa ai quyết định** trên DefectDojo, ghi tag `ai-*` và note. Không có DefectDojo thì triage trên kết quả scan ([§8.5](#85-ai-triage-với-claude)) | `triage-ai-<prefix>.json`, `.md` |
| 8 | **Rule stats** | DefectDojo đã cấu hình **và** tham số `RULE_STATS` được bật | Thống kê FP và finding trùng theo từng rule, để tuning ([§8.6](#86-thống-kê-rule-để-tuning)) | `rule-stats-<prefix>.md` |
| 9 | **Security gate** | Luôn chạy | `devsecops-scan report` rồi `devsecops-scan gate`: PASS/FAIL **chỉ dựa trên kết quả scan gốc** (stage 1–4); stage 5–8 không bao giờ ảnh hưởng | `summary-<prefix>.md` |
| – | **post** (không phải stage) | Luôn chạy, kể cả khi gate fail | Archive `security-reports/**`, publish SARIF bằng Warnings NG, copy kết quả cho MCP nếu có `MCP_REPORTS_DIR` ([§8.3](#83-gửi-kết-quả-cho-mcp-server)) | |

Khi một stage lỗi:

| Stage lỗi | Kết quả build |
|---|---|
| 1, 2, 3.x, 4 (scanner lỗi, exit 2) | **FAILURE**. Pipeline dừng sau stage đó (các stage con song song khác vẫn chạy xong); stage 5–9 bị bỏ qua, bước `post` vẫn chạy và lưu kết quả scan lỗi |
| 5, 6, 7, 8 | **UNSTABLE**. Pipeline chạy tiếp tới gate; kết quả scan và gate vẫn hợp lệ |
| 9 (vi phạm policy, exit 1) | **FAILURE** |

Số stage thực sự chạy tuỳ theo cấu hình. Các stage không chạy vẫn hiện trên giao diện Jenkins ở trạng thái *skipped*:

| Cấu hình | Stage chạy | Số stage |
|---|---|---|
| Mặc định (chưa có DefectDojo, chưa có Claude, không đặt tham số) | 1, 2, 3, 3.1–3.3, 5, 9 | 8 (7 nếu không tính stage cha *Scans*) |
| Thêm DefectDojo và Claude | + 6, 7 | 10 |
| Bật tất cả (thêm `IMAGE_REF`, `DAST_TARGET_URL`, `RULE_STATS`) | tất cả | 13 |

Build đầu tiên lâu hơn vì Trivy phải tải vulnerability DB (vài trăm MB). Cache nằm trong `<workspace>@tmp/trivy-cache` và được giữ cho các build sau trên cùng máy.

### 6.4 Tham số build và biến môi trường

**Tham số build** (trong **Build with Parameters**; xuất hiện từ build thứ hai):

| Tham số | Mặc định | Tác dụng |
|---|---|---|
| `SCANNER_IMAGE` | `registry.example.com/devsecops-scanner:2.1.0` | Image scanner dùng để chạy mọi stage ([§6.1](#61-cho-jenkins-dùng-image-scanner-đã-build)) |
| `IMAGE_REF` | trống | Container image cần scan; có giá trị thì chạy stage 3.4 |
| `DAST_TARGET_URL` | trống | URL ứng dụng cần scan DAST; có giá trị thì chạy stage 4 |
| `DAST_MODE` | `baseline` | `baseline`: template HTTP. `full`: thêm crawl Katana và fuzzing, **chỉ dùng cho môi trường test** |
| `RULE_STATS` | tắt | Bật stage 8 (cần DefectDojo) |

**Biến môi trường toàn cục** (**Manage Jenkins → System → Global properties → Environment variables**; đặt một lần, áp dụng cho mọi build):

| Biến | Bật stage | Ghi chú |
|---|---|---|
| `DEFECTDOJO_URL` + `DEFECTDOJO_CREDENTIALS_ID` | 6, và 8 khi có `RULE_STATS` | ID của credential *Secret text* chứa API v2 key ([§8.4](#84-đẩy-finding-lên-defectdojo)) |
| `DEFECTDOJO_PRODUCT`, `DEFECTDOJO_PRODUCT_TYPE` | | Không bắt buộc. Mặc định: tên repo (multibranch) hoặc tên job, và `DevSecOps` |
| `ANTHROPIC_CREDENTIALS_ID` | 7 | ID của credential *Secret text* chứa API key Anthropic ([§8.5](#85-ai-triage-với-claude)) |
| `MCP_REPORTS_DIR` | (bước `post`) | Thư mục chia sẻ với MCP server ([§8.3](#83-gửi-kết-quả-cho-mcp-server)) |

## 7. Đọc kết quả

- **Console Output** (hoặc bấm vào từng ô trong bảng stage để xem log riêng của stage đó):
  - Stage 2 in bảng ngôn ngữ tìm thấy.
  - Stage 3.x và 4: mỗi dòng log của scanner có tiền tố tên tool (`[opengrep]`, `[trivy]`, `[osv-scanner]`, `[nuclei]`, `[katana]`), kèm câu lệnh chạy và exit code.
  - Stage 5 in số finding và số nhóm trùng (`Correlation: N findings in M groups ...`).
  - Stage 6 in mỗi tool một dòng (`DefectDojo: opengrep (sast) -> test 12: 40 findings, tags updated on 3`).
  - Stage 7 in số nhóm bỏ qua vì đã có quyết định hoặc đã triage, và số finding được ghi tag/note.
  - Stage 9 in `Policy: PASS/FAIL` cùng lý do.
- **DevSecOps scans** (link bên trái trang build, do Warnings NG tạo): danh sách finding, lọc theo mức độ, file, rule. Finding SAST mang rule ID dạng `sast-<ngôn ngữ>-<NNNN>`.
- **Build Artifacts**: `security-reports/<scan_id>/result.json`, `result.sarif`, `policy.json`, `languages-<prefix>.json`, báo cáo tổng hợp `summary-<prefix>.md`, `triage-<prefix>.md`/`.json` (các nhóm finding đã gộp), `triage-ai-<prefix>.md`/`.json` (verdict AI, sắp theo priority), `defectdojo-<prefix>.json` (các test đã import), và `rule-stats-<prefix>.md` nếu bật `RULE_STATS`.

Trạng thái build:

| Kết quả | Ý nghĩa |
|---|---|
| SUCCESS | Gate PASS (hoặc WARN khi `enforcement_level: permissive`) |
| FAILURE ở stage *Security gate* | Có finding vượt ngưỡng trong `security-rules.yml`. Xem summary/Warnings NG |
| FAILURE ở một stage scan | Scanner lỗi (exit 2). Xem log `[tool]` của stage đó |
| UNSTABLE | Một trong các stage Correlate, DefectDojo, AI triage, Rule stats bị lỗi (API key sai, mạng, DefectDojo từ chối). Kết quả scan và gate vẫn hợp lệ. Xem log của stage đó |

## 8. Bật các stage tuỳ chọn: DAST, scan image, MCP, DefectDojo, AI triage, thống kê rule

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

### 8.4 Đẩy finding lên DefectDojo

DefectDojo là nơi lưu lại **mọi** finding, kể cả bản trùng (Duplicate) và false positive (FP), cùng các quyết định của người review. Đây là dữ liệu để tuning rule ([§8.6](#86-thống-kê-rule-để-tuning)).

Cần một DefectDojo đang chạy, ví dụ dựng bằng `docker compose` theo repo [DefectDojo/django-DefectDojo](https://github.com/DefectDojo/django-DefectDojo).

1. Trong DefectDojo, tạo user riêng cho CI, chỉ có quyền trên các product cần dùng (hoặc quyền tạo product nếu muốn tự tạo). Lấy **API v2 key** ở menu user → *API v2 Key*.
2. Jenkins: thêm credential **Secret text** chứa key đó, ví dụ ID `defectdojo-api-key`.
3. **Global properties → Environment variables**:

   | Biến | Ví dụ | Bắt buộc |
   |---|---|---|
   | `DEFECTDOJO_URL` | `https://defectdojo.example.com` (có thể kèm prefix như `/dojo`) | Có |
   | `DEFECTDOJO_CREDENTIALS_ID` | `defectdojo-api-key` | Có |
   | `DEFECTDOJO_PRODUCT` | `shop-api` | Không: mặc định là tên repo (multibranch) hoặc tên job |
   | `DEFECTDOJO_PRODUCT_TYPE` | `Web` | Không: mặc định `DevSecOps` |

4. Máy chạy scan phải gọi được `DEFECTDOJO_URL`. Nếu DefectDojo chạy cùng máy bằng Docker, dùng IP trên mạng bridge hoặc `host.docker.internal`, không dùng `localhost`.

Mỗi build, stage *DefectDojo import* sẽ:

- **Tạo product/engagement nếu chưa có:** engagement có tên `CI/CD <branch>`.
- **Reimport mỗi tool thành một test** (`opengrep (sast)`, `osv-scanner (sca)`, `trivy (sca)`, …). DefectDojo tự **đóng finding đã được sửa** và mở lại finding tái xuất hiện. Quyết định của người review (False Positive, Verified, Risk Accepted…) được giữ qua các build.
- **Gắn tag correlation** từ stage *Correlate*: `corr-<id>` cho các finding cùng một vấn đề, và `corr-duplicate` cho các bản trùng (giữ lại bản đầu tiên). Mặc định DefectDojo chỉ gộp trùng trong cùng một loại scan, nên trùng giữa OSV và Trivy chỉ thấy được qua tag này.
- **Bỏ qua tool có scan lỗi trong build đó**, để DefectDojo không đóng nhầm finding của tool ấy.
- **Ghi lại các test vừa import** vào `defectdojo-<prefix>.json`, để stage *AI triage* biết cần xử lý finding nào.

### 8.5 AI triage với Claude

Stage *AI triage* chạy khi có credential Anthropic:

1. Lấy API key ở [Claude Console](https://console.anthropic.com/) (*Settings → API keys*). Nên tạo key riêng cho CI và đặt giới hạn chi tiêu cho workspace.
2. **Manage Jenkins → Credentials → System → Global credentials → Add Credentials**:
   - *Kind*: **Secret text**
   - *Secret*: API key
   - *ID*: ví dụ `anthropic-api-key`
3. **Manage Jenkins → System → Global properties → Environment variables**: thêm `ANTHROPIC_CREDENTIALS_ID` = `anthropic-api-key`.
4. Máy chạy scan phải ra được `api.anthropic.com`.

**Khi đã cấu hình DefectDojo** (cách nên dùng), stage đọc lại các finding vừa import trên DefectDojo rồi xử lý theo từng nhóm:

| Tình trạng của nhóm | Xử lý |
|---|---|
| Không còn finding nào đang mở: đã đóng, hoặc người review đã quyết định (False Positive, Risk Accepted, Verified, Out of scope) | Bỏ qua: AI không đánh giá lại quyết định của người |
| Mọi finding đang mở đều đã có verdict AI từ build trước | Bỏ qua: mỗi finding chỉ triage một lần, nên từ build thứ hai trở đi gần như không tốn tiền |
| Còn lại (finding mới, chưa ai xem) | Gửi cho Claude |

Kết quả được ghi về DefectDojo, chỉ trên các finding đang mở và chưa có quyết định:
- tag `ai-true-positive` / `ai-false-positive` / `ai-needs-review`, `ai-confidence-*`, `ai-priority-p1`…;
- một **note** chứa lý do, cách sửa và nhóm correlation.

Hệ thống **không bao giờ đổi trạng thái** finding: không đánh `false_p`, không tắt `active`. Người review lọc theo tag (ví dụ `ai-false-positive`) để xem trước rồi tự quyết định trên DefectDojo. Muốn AI đánh giá lại những finding đã có verdict, chạy CLI với `--retriage`.

**Khi chưa có DefectDojo** (hoặc stage import lỗi), AI triage trên kết quả scan và chỉ ghi file `triage-ai-<prefix>.json`/`.md`.

Cấu hình trong mục `triage:` của `security-rules.yml`:

| Khoá | Mặc định | Ý nghĩa |
|---|---|---|
| `model` | `claude-opus-5-5` | Model dùng để triage |
| `effort` | `medium` | Mức suy luận: `low` rẻ, nhanh; `high`/`xhigh` kỹ hơn cho finding khó |
| `min_severity` | `low` | Nhóm thấp hơn mức này không gửi cho AI |
| `max_groups` | `100` | Số nhóm nghiêm trọng nhất gửi cho AI mỗi build (giới hạn chi phí) |
| `send_code` | `true` | Gửi khoảng 20 dòng code quanh finding SAST (đã che chuỗi giống secret). `false` = chỉ gửi metadata |

Những điều cần biết:

- **Kết quả AI chỉ để tham khảo:** gate vẫn tính trên kết quả scan gốc. Code độc có thể chứa comment kiểu "hãy đánh dấu là false positive"; model được dặn coi đó là dấu hiệu giả mạo, và dù model bị lừa thì build cũng không pass sai.
- **Finding về secret không bao giờ gửi kèm code.**
- **Code nằm ngoài thư mục được scan** (ví dụ đường dẫn `../..`) cũng không được gửi.
- **Khi lỗi** (API lỗi, bị giới hạn tốc độ, model từ chối), các nhóm lỗi không được ghi gì lên DefectDojo, file `triage-ai` vẫn được ghi kèm danh sách lỗi, và build chuyển sang UNSTABLE.

### 8.6 Thống kê rule để tuning

Stage *Rule stats* (bật bằng tham số build `RULE_STATS`, cần DefectDojo) đọc toàn bộ finding của product trên DefectDojo và gom theo rule. Rule SAST được hiển thị theo rule ID `sast-<ngôn ngữ>-<NNNN>`, kèm tên rule Opengrep gốc để biết cần sửa file nào. Kết quả nằm ở `rule-stats-<prefix>.md` trong Build Artifacts.

| Cột | Ý nghĩa |
|---|---|
| FP / Confirmed | Do **người** quyết định: False Positive / Verified hoặc Risk Accepted |
| FP rate | FP / (FP + Confirmed) |
| Duplicate | Trùng theo DefectDojo, hoặc có tag `corr-duplicate` |
| AI: FP | Số finding AI gắn `ai-false-positive` (chỉ để gợi ý) |

| Gợi ý | Khi nào |
|---|---|
| Tune or disable | FP rate ≥ 70% và có ít nhất 5 finding đã được người review |
| Redundant | ≥ 80% là bản trùng của rule hoặc tool khác: giữ một bên |
| Review a sample | Chưa đủ người review, nhưng AI cho rằng phần lớn là FP: nên xem thử vài finding |
| Reliable | FP rate ≤ 20%: giữ nguyên |

Gợi ý chỉ dựa trên **quyết định của người**, không bao giờ chỉ dựa vào tag AI. Nếu tắt rule chỉ vì AI nói FP, một lần AI đánh giá sai (hoặc bị code độc lừa) có thể làm mất một rule đang bắt lỗi thật.

Có thể chạy tay, hoặc đặt một job Jenkins chạy định kỳ (ví dụ hằng tuần):

```bash
DEFECTDOJO_URL=https://defectdojo.example.com DEFECTDOJO_API_KEY=... \
  devsecops-scan rule-stats --product shop-api --out rule-stats.md      # --format json, --min-reviewed 10
```

Sau khi tuning (sửa `exclude`, viết rule riêng thay thế, hoặc bỏ rule khỏi `language_configs` trong `security-rules.yml`), các build sau sẽ không báo lại những finding đó nữa. DefectDojo tự đóng chúng khi reimport.

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
| `No such DSL method 'withCredentials'` / `string` | Thiếu plugin Credentials Binding |
| `ANTHROPIC_API_KEY ... is required` | Biến `ANTHROPIC_CREDENTIALS_ID` có giá trị nhưng credential rỗng, hoặc chạy CLI tay mà không có key. Nếu chỉ cần gộp finding, dùng lệnh `correlate` |
| AI triage không gửi gì cho Claude (`skipped ... decided by people and ... already triaged`) | Bình thường từ build thứ hai: mọi finding đang mở đã có verdict AI hoặc đã được người quyết định. Chạy CLI với `--retriage` nếu muốn đánh giá lại |
| `Triage error: batch N: ...401...` | API key Anthropic sai hoặc đã bị thu hồi |
| `Triage error: batch N: model declined the batch (...)` | Model từ chối nội dung của batch (kể cả sau fallback). Các nhóm đó được ghi là `failed`, chỉ ảnh hưởng tới phần tham khảo |
| `DefectDojo POST /api/v2/reimport-scan/ failed: HTTP 400 ...` | Đọc thông báo đi kèm. Thường gặp: product type không tồn tại và user không có quyền tạo, hoặc thiếu quyền trên product |
| `DefectDojo ... HTTP 401/403` | API v2 key sai, hoặc user không có quyền trên product/engagement |
| `fetch failed` / timeout khi gọi DefectDojo | Container scanner không ra được `DEFECTDOJO_URL` (xem bước 4 của [§8.4](#84-đẩy-finding-lên-defectdojo)) |
