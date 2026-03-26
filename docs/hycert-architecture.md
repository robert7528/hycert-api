# hycert 憑證管理系統架構

## 核心元件關係圖

```
┌─────────────────────────────────────────────────────────────┐
│                     hycert Web UI                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────────┐  │
│  │ 憑證管理 │ │ CSR 管理 │ │ 部署目標 │ │ Token/Agent   │  │
│  │          │ │          │ │          │ │ 管理          │  │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └───────┬───────┘  │
└───────┼────────────┼────────────┼───────────────┼───────────┘
        │            │            │               │
        ▼            ▼            ▼               ▼
┌─────────────────────────────────────────────────────────────┐
│                     hycert API                              │
│                                                             │
│  certificates  csrs  deployments  agent-tokens  registrations│
│       │                   │             │            │      │
│       │         ┌─────────┘             │            │      │
│       │         │                       │            │      │
│       ▼         ▼                       ▼            ▼      │
│  ┌─────────────────────┐    ┌────────────────────────┐      │
│  │    Tenant DB         │    │     Admin DB           │      │
│  │  ・certificates      │    │  ・agent_tokens        │      │
│  │  ・csrs              │    │                        │      │
│  │  ・deployments       │    │                        │      │
│  │  ・deployment_history│    │                        │      │
│  │  ・agent_registrations│   │                        │      │
│  └─────────────────────┘    └────────────────────────┘      │
└─────────────────────────────────────────────────────────────┘
        ▲                           ▲
        │ Agent API                 │ Token 認證
        │ (X-Agent-ID header)       │ (Authorization: Bearer)
        │                           │
┌───────┴───────────────────────────┴─────────────────────────┐
│                   hycert-agent (Go binary)                  │
│                                                             │
│  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌─────────────┐  │
│  │ Register │  │ 拉取部署 │  │ 下載憑證 │  │ 回報狀態    │  │
│  │ 心跳     │  │ 目標     │  │ 寫檔     │  │ fingerprint │  │
│  └─────────┘  └──────────┘  └──────────┘  └─────────────┘  │
│                                                             │
│  設定檔：agent.yaml          身份檔：agent-id               │
└─────────────────────────────────────────────────────────────┘
```

## 資料模型關係

```
Token (hycert_agent_tokens)
  │
  │  1:N（一個 token 被多個 agent 共用）
  │
  ├── Agent (hycert_agent_registrations)
  │     │
  │     │  1:N（一個 agent 有多個部署目標）
  │     │
  │     └── Deployment (hycert_deployments)
  │           │
  │           │  N:1（多個部署指向同一張憑證）
  │           │
  │           └── Certificate (hycert_certificates)
  │
  │  label 過濾
  │
  └── Deployment.label ←→ Token.label（匹配規則）
```

## Token ↔ Agent ↔ Deployment 關係

### 對應關係

| 關係 | 型態 | 說明 |
|------|------|------|
| Token → Agent | 一對多 | 多個 agent 共用同一個 token（同一份 yaml token 值） |
| Token → Label | 一對一 | 一個 token 只有一個 label |
| Agent → Deployment | 一對多 | 一個 agent 負責多個部署目標（nginx + tomcat 等） |
| Deployment → Certificate | 多對一 | 多個部署可以使用同一張憑證 |
| Deployment → Agent | 多對一 | 一個部署只綁定一個 agent |

### Label 過濾規則（寬鬆模式）

| Token label | Deployment label | Agent 拉得到？ | 說明 |
|-------------|------------------|----------------|------|
| 空 | 空 | ✅ | 都沒設 label，匹配 |
| 空 | customer-A | ✅ | 空 = 萬用，匹配所有 |
| customer-A | 空 | ✅ | 空 = 萬用，匹配所有 |
| customer-A | customer-A | ✅ | 相同 label，匹配 |
| customer-A | customer-B | ❌ | 不同 label，不匹配 |

## Agent 輪詢流程

```
Agent 啟動（daemon 模式）
  │
  ▼
每隔 interval 秒（預設 3600）
  │
  ├─ 1. Register（心跳）
  │    POST /api/v1/agent/cert/register
  │    Header: Authorization: Bearer {token}, X-Agent-ID: {agent_id}
  │    Body: { agent_id, name, hostname, ip_addresses, os, version, interval }
  │    → Server 更新 last_seen_at（判斷在線/離線）
  │
  ├─ 2. 拉取部署目標
  │    GET /api/v1/agent/cert/deployments
  │    Header: Authorization: Bearer {token}, X-Agent-ID: {agent_id}
  │    → Server 檢查：
  │       ・Agent status（disabled → 403 拒絕）
  │       ・Token label 過濾 deployment
  │    → 回傳 deployment 列表（含 cert_fingerprint + last_fingerprint）
  │
  ├─ 3. 逐筆比對 fingerprint
  │    cert_fingerprint == last_fingerprint → 跳過（已是最新）
  │    cert_fingerprint != last_fingerprint → 需要部署
  │
  ├─ 4. 下載憑證
  │    GET /api/v1/agent/cert/certificates/{id}/download?format=pem|jks
  │    → 取得 cert + key
  │
  ├─ 5. 部署
  │    ・備份現有憑證（{service}-{id}/ 子目錄）
  │    ・寫入新憑證（key 檔案 0600 權限）
  │    ・執行 reload 指令（nginx -s reload / systemctl restart 等）
  │
  └─ 6. 回報狀態
       PUT /api/v1/agent/cert/deployments/{id}/status
       Body: { action: "deploy", status: "success|failed", fingerprint, duration_ms }
       → Server 更新 deploy_status + last_fingerprint + 寫入 deployment_history
```

## Agent YAML 設定檔

```yaml
# agent.yaml
server:
  url: "https://domain.com/hycert-api"    # hycert API 位址
  token: "hycert_agt_xxxx..."              # Agent Token（認證用）
  proxy: ""                                 # HTTP Proxy（可選）
  insecure_skip_verify: false               # 跳過 SSL 驗證

agent:
  name: "web-server-01"                     # 顯示名稱（UI 辨識用）
  interval: 3600                            # 輪詢間隔（秒）
  backup: true                              # 部署前備份
  backup_dir: "/var/lib/hycert-agent/backups"  # 備份目錄

log:
  level: "debug"                            # 日誌等級
  file: "/var/log/hycert-agent/agent.log"   # 日誌檔案
  max_size: 10                              # 單檔上限（MB）
  max_backups: 3                            # 保留數量
  max_age: 30                               # 保留天數
  compress: true                            # 壓縮舊日誌
```

## Agent-ID 檔案

```
# /etc/hycert/agent-id（Linux）
# D:\hycert-agent\agent-id（Windows）

0ddfc57e-62cc-4b36-88fa-e845cc47f283
machine:a1b2c3d4e5f67890a1b2c3d4e5f67890
```

| 行 | 內容 | 說明 |
|----|------|------|
| 第 1 行 | UUID | Agent 唯一識別碼，首次啟動自動產生 |
| 第 2 行 | machine:{id} | 主機識別碼，防止複製目錄導致 agent-id 重複 |

- agent-id 不在 yaml 裡，獨立檔案，重裝不影響
- machine-id 來源：Linux `/etc/machine-id`，Windows `Registry MachineGuid`

## 部署目標 target_detail 結構

### PEM 分開（nginx / apache）

```json
{
  "os": "linux",
  "cert_path": "/etc/nginx/ssl/cert.pem",
  "key_path": "/etc/nginx/ssl/key.pem",
  "reload_cmd": "nginx -s reload"
}
```

### PEM 分開（hyproxy）

```json
{
  "os": "linux",
  "cert_path": "/hyproxy/ssl/cert.pem",
  "key_path": "/hyproxy/ssl/key.pem",
  "reload_cmd": "systemctl restart hyproxy"
}
```

### PEM 合併（haproxy）

```json
{
  "os": "linux",
  "cert_path": "/etc/haproxy/ssl/cert.pem",
  "reload_cmd": "systemctl restart haproxy"
}
```

### JKS（tomcat）

```json
{
  "os": "windows",
  "cert_path": "D:/tomcat/conf/keystore.jks",
  "password": "changeit",
  "alias": "tomcat",
  "reload_cmd": "net stop Tomcat8 && net start Tomcat8"
}
```

### K8S TLS Secret（待實作）

```json
{
  "os": "linux",
  "secret_name": "my-tls-secret",
  "namespace": "default",
  "kubeconfig": "/root/.kube/config"
}
```

## Token 管理

### Token 欄位

| 欄位 | 說明 |
|------|------|
| name | 顯示名稱（如 `token-web-server-01`） |
| token_hash | SHA-256 雜湊（認證比對用，不可逆） |
| token_encrypted | Tink 加密明文（可解密取回，用於重用） |
| token_prefix | 前 19 碼（`hycert_agt_` + 8 hex，UI 辨識用） |
| label | 分群標籤（customer-A、prod 等） |
| status | active / revoked |
| expires_at | 到期時間（null = 永不過期） |
| last_used_at | 最後使用時間（Agent 認證時更新） |

### Token 生命週期

```
建立 → active
  │
  ├─ 停用（revoke）→ revoked（Agent 認證失敗，資料保留）
  │
  └─ 刪除（delete）→ 硬刪除（僅限無 Agent 綁定時）
```

### Token 重用機制

```
安裝 Agent 時輸入 label
  → 查詢 GET /agent-tokens/by-label/{label}
  → 找到 → 解密 token_encrypted → 重用（寫入 yaml）
  → 沒找到 → 建新 token → 寫入 yaml
```

同一個 label 下的多台主機共用同一個 token。

## 完整使用場景

### 場景：新客戶「甲公司」有 3 台主機需要部署憑證

```
1. 管理者在 UI 匯入甲公司的 SSL 憑證

2. 到甲公司第 1 台主機安裝 Agent：
   → 輸入 label: "甲公司"
   → 自動建立 token（token-甲-web-01, label: 甲公司）
   → Agent 註冊成功

3. 到甲公司第 2 台主機安裝 Agent：
   → 輸入 label: "甲公司"
   → 查到已有 token → 重用（不建新的）
   → Agent 註冊成功

4. 到甲公司第 3 台主機安裝 Agent：
   → 同上，重用同一個 token

5. 管理者在 UI 建立 3 筆部署目標：
   → 憑證: 甲公司 SSL
   → Agent: 甲-web-01 / 甲-web-02 / 甲-web-03
   → Label: 甲公司
   → 設定各自的部署路徑

6. 3 台 Agent 下次輪詢時自動部署憑證

7. 憑證到期前，管理者匯入新憑證（或 ACME 自動續約）
   → fingerprint 變更
   → Agent 偵測到 → 自動下載新憑證 → 部署 → 回報

8. 如果要停止甲公司的自動部署：
   方式 A：停用 token → 所有 Agent 無法認證
   方式 B：逐一停用 Agent → 精細控制
   方式 C：刪除部署目標 → 不影響 Agent，只是沒東西部署
```

## 支援的部署類型

| target_service | 格式 | 部署方式 | 狀態 |
|----------------|------|----------|------|
| nginx | PEM 分開 | cert + key 分別寫檔 → reload | ✅ Phase 1 |
| apache | PEM 分開 | cert + key 分別寫檔 → reload | ✅ Phase 1 |
| hyproxy | PEM 分開 | cert + key 分別寫檔 → reload（同 nginx） | ✅ Phase 1 |
| haproxy | PEM 合併 | cert + key 合併寫入一個檔案 → reload | ✅ Phase 1 |
| tomcat | JKS | 下載 JKS keystore → 寫檔 → 重啟 | ✅ Phase 2 |
| iis | PFX | 下載 PFX → 匯入 → 綁定 → 重啟 | 待做 Phase 2 |
| kubernetes | TLS Secret | kubectl create secret tls → apply | 待做 Phase 2 |

## 檔案路徑對照

### Linux

| 檔案 | 路徑 |
|------|------|
| Binary | `/usr/local/bin/hycert-agent` |
| Config | `/etc/hycert/agent.yaml` |
| Agent-ID | `/etc/hycert/agent-id` |
| Backups | `/var/lib/hycert-agent/backups/` |
| Logs | `/var/log/hycert-agent/agent.log` |
| Service | systemd（kardianos/service） |

### Windows

| 檔案 | 路徑 |
|------|------|
| Binary | `D:\hycert-agent\hycert-agent-windows-amd64.exe` |
| Config | `D:\hycert-agent\agent.yaml` |
| Agent-ID | `D:\hycert-agent\agent-id` |
| Backups | `D:\hycert-agent\backups\` |
| Logs | `D:\hycert-agent\logs\agent.log` |
| Service | Windows Service（kardianos/service） |

## 管理功能與狀態說明

### 部署目標（Deployments）

管理「哪張憑證部署到哪台主機的哪個服務」。

#### 狀態欄位

| 欄位 | 值 | 說明 | 設定方式 |
|------|-----|------|----------|
| `status` | `active` | 使用中，Agent 會拉取 | 人工（建立時預設） |
| `status` | `disabled` | 停用中，Agent 不會拉取 | 人工（編輯時切換） |
| `deploy_status` | `pending` | 已建立，等待 Agent 拉取 | 系統（建立時預設） |
| `deploy_status` | `deployed` | Agent 已成功部署 | 系統（Agent 回報成功） |
| `deploy_status` | `failed` | Agent 部署失敗 | 系統（Agent 回報失敗） |

#### 操作

| 操作 | 效果 |
|------|------|
| 編輯 | 修改主機、服務、路徑、Agent、Label、狀態（active/disabled） |
| 刪除 | 軟刪除，從列表消失（DB 保留 `deleted_at`） |
| 展開 | 查看 deployment_history（每次部署的時間、結果、fingerprint、耗時） |

#### deploy_status 自動變更情境

- 建立 → `pending`
- Agent 部署成功 → `deployed`
- Agent 部署失敗 → `failed`
- 管理者更換憑證 → Agent 下次偵測到 fingerprint 變更 → 重新部署 → 更新狀態

---

### Agent 管理（Registrations）

管理已註冊的 Agent 主機。

#### 狀態欄位

| 欄位 | 值 | 說明 | 設定方式 |
|------|-----|------|----------|
| `status` | `active` | 正常運作，可拉取 deployments | 系統（首次註冊時預設） |
| `status` | `disabled` | 停用，無法拉取（API 回 403） | 人工（UI 停用按鈕） |
| 在線/離線 | 在線 | `last_seen_at` 在 `poll_interval * 2` 內 | 系統（Agent 心跳自動更新） |
| 在線/離線 | 離線 | `last_seen_at` 超過閾值 | 系統（Agent 未心跳，前端計算） |

#### 操作

| 操作 | 效果 |
|------|------|
| 停用 | Agent 無法拉取 deployments（403），server log 記錄嘗試 |
| 啟用 | 恢復正常拉取 |

#### 自動變更情境

- Agent 啟動 → 自動註冊（`active`），更新 `last_seen_at`
- Agent 每次輪詢 → 更新 `last_seen_at`、hostname、IP、OS、version
- Agent 停止運作 → 超過閾值後 UI 顯示「離線」（DB 不變，前端計算）
- 人工停用後 Agent 仍會心跳 → `last_seen_at` 繼續更新，但拉取 deployments 被拒

---

### Token 管理（Agent Tokens）

管理 Agent 的認證憑據。

#### 狀態欄位

| 欄位 | 值 | 說明 | 設定方式 |
|------|-----|------|----------|
| `status` | `active` | 有效，Agent 可認證 | 人工（建立時預設） |
| `status` | `revoked` | 已停用，Agent 認證失敗 | 人工（UI 停用按鈕） |
| `last_used_at` | 時間戳 | 最後一次 Agent 用此 token 認證的時間 | 系統（Agent 每次輪詢帶 token 打 API 時自動更新） |
| `expires_at` | 時間戳/null | 到期時間，過期後認證失敗 | 人工（建立時設定，null = 永不過期） |

#### 操作

| 操作 | 效果 |
|------|------|
| 建立 | 產生新 token（name + label + 可選到期日），顯示明文供複製 |
| 編輯 | 修改名稱和 label |
| 顯示 | 解密顯示 token 明文（可再次複製） |
| 停用（revoke） | token 失效，所有用這個 token 的 Agent 都無法認證 |
| 刪除 | 永久刪除（僅限無 Agent 綁定時） |

#### 自動變更情境

- Agent 每次輪詢帶 token 認證 → 更新 `last_used_at`
- `expires_at` 到期 → 認證自動失敗（`status` 不變，API 檢查時間判定）

---

### 三層管控總覽

```
Token 停用 → 影響該 token 下所有 Agent 都無法認證（最大範圍：整個 label 群組）
Agent 停用 → 只影響這一個 Agent 無法拉取（中：單台主機）
部署目標停用 → 只影響這一筆部署不再執行（最小：單個服務）
部署目標刪除 → 從列表消失（最小：單個服務）
```

| 場景 | 操作 |
|------|------|
| 整個客戶停止服務 | 停用 Token |
| 某台主機下線維護 | 停用 Agent |
| 某個服務不再需要憑證 | 停用或刪除部署目標 |
| 憑證到期要更換 | 匯入新憑證 → Agent 自動偵測並部署 |

### 狀態設定方式總覽

| 狀態 | 設定方式 | 說明 |
|------|----------|------|
| Deployment `status` | 人工 | 管理者決定啟用或停用部署 |
| Deployment `deploy_status` | 系統 | Agent 回報部署結果，管理者不可直接修改 |
| Agent `status` | 人工 | 管理者決定啟用或停用 Agent |
| Agent 在線/離線 | 系統 | 根據心跳時間自動計算，非 DB 欄位 |
| Token `status` | 人工 | 管理者決定啟用或停用 Token |
| Token `last_used_at` | 系統 | Agent 每次輪詢認證時自動更新 |
| Token `expires_at` | 人工 | 建立時設定，到期後系統自動拒絕認證 |
