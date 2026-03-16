# hycert-api

## Development Environment

- **Windows local**: Source code editing only. No Go runtime available.
- **GitHub**: `robert7528/hycert-api`
- **CI/CD**: GitHub Actions → build & push `ghcr.io/robert7528/hycert-api:latest`
- **Deploy**: Linux API server (`/hysp/hycert-api/`) via Podman Quadlet + systemctl.

## Project Structure

```
hycert-api/
├── cmd/
│   └── server/main.go          # Cobra CLI → app.Run()
├── internal/
│   ├── app/app.go              # fx DI 組裝（無 DB、無 Casbin）
│   ├── server/server.go        # Gin routes + fx Lifecycle
│   ├── health/handler.go       # GET /api/v1/health
│   ├── chain/
│   │   ├── builder.go          # ChainBuilder（AIA chasing + AKID/SKID）
│   │   ├── rootstore.go        # 系統 Root CA 庫（x509.SystemCertPool）
│   │   └── fetcher.go          # AIA HTTP fetcher + in-memory cache
│   ├── parser/
│   │   └── parser.go           # 憑證格式偵測 + 解析（PEM/DER）
│   └── utility/
│       ├── model.go            # Request/Response DTOs
│       ├── service.go          # 業務邏輯（verify / parse / generate-csr）
│       └── handler.go          # HTTP handlers
├── configs/config.yaml
├── deployment/
│   ├── deploy.sh
│   ├── entrypoint.sh
│   ├── hycert-api.container    # Podman Quadlet
│   ├── api.env.example
│   └── nginx-hycert-api.conf
├── Containerfile               # Go builder + Alpine runner（含 ca-certificates）
└── .github/workflows/build.yml
```

## Tech Stack

- **Runtime**: Go + uber-go/fx (DI) + Gin (HTTP) + Cobra/Viper (CLI/config) + zap
- **Cert Parsing**: Go `crypto/x509`（PEM/DER）
- **Auth**: hycore JWT middleware（共用 hyadmin-api 的 JWT_SECRET，僅驗證不簽發）
- **無 DB**: P1 為純 Utility API，無需資料庫

## Route Structure

```
/api/v1/health                          # Public: health check
/api/v1/adm/cert/utility/verify         # Admin: 憑證檢核
/api/v1/adm/cert/utility/parse          # Admin: 憑證解析
/api/v1/adm/cert/utility/convert        # Admin: 格式轉換（TODO）
/api/v1/adm/cert/utility/generate-csr   # Admin: 產生 CSR
/api/v1/agent/cert/...                  # Agent: 未來 Agent 輪詢端點
/api/v1/pub/cert/...                    # Public: 未來外部 API
```

## Key Design Decisions

- **私鑰安全**：API Server 不儲存、不記錄任何私鑰
- **JWT 共用**：JWT_SECRET 需與 hyadmin-api 一致，使用 hycore auth middleware 驗證
- **ChainBuilder**：AIA Chasing + AKID/SKID 比對 + 系統 Root CA 庫
- **AIA Cache**：in-memory（sync.Map），TTL 24 小時
- **Containerfile**：runtime stage 需安裝 `ca-certificates`（供 SystemCertPool + AIA fetching）

## Environment Variables

| 變數 | 預設值 | 說明 |
|------|--------|------|
| `SERVER_PORT` | `8082` | 服務 port |
| `SERVER_MODE` | `debug` | Gin mode |
| `JWT_SECRET` | — | JWT 密鑰（必須與 hyadmin-api 一致） |
| `LOG_LEVEL` | `debug` | 日誌等級 |

## Deploy

```bash
# 第一次
git clone https://github.com/robert7528/hycert-api.git /hysp/hycert-api
sudo bash /hysp/hycert-api/deployment/deploy.sh
# → 會建立 /etc/hycert/api.env，填入 JWT_SECRET 後再跑一次

# 更新
cd /hysp/hycert-api
sudo bash deployment/deploy.sh
```

## nginx

- 路徑：`/hycert-api/` → `http://127.0.0.1:8082/`
- **trailing slash**：nginx 剝離前綴，Gin 收到 `/api/v1/...`
