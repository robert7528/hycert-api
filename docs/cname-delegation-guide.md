# SSL 憑證自動續約 — CNAME 委派設定指南

## 概述

本指南說明如何設定 DNS CNAME 記錄，將 SSL 憑證的 ACME 驗證委派至指定的 DNS 進行處理。設定完成後，SSL 憑證的申請、續約、部署皆由系統自動完成，無需每次人工配合。

此設定為**一次性**，設定後長期有效。

---

## 設定步驟

### 1. 新增 CNAME 記錄

請針對每個需要自動化的域名，在 DNS 新增一筆 CNAME 記錄：

| 欄位 | 內容 |
|---|---|
| 類型 | CNAME |
| 名稱 | `_acme-challenge.【客戶域名】` |
| 值 | `_acme-challenge.【客戶域名】.acme.k00.com.tw.` |
| TTL | 預設值即可（或填 3600） |

#### 設定範例

以 `hylib.example.edu.tw` 和 `hyproxy.example.edu.tw` 為例：

| 名稱（Name） | 類型 | 目標值（Value） |
|---|---|---|
| `_acme-challenge.hylib.example.edu.tw` | CNAME | `_acme-challenge.hylib.example.edu.tw.acme.k00.com.tw.` |
| `_acme-challenge.hyproxy.example.edu.tw` | CNAME | `_acme-challenge.hyproxy.example.edu.tw.acme.k00.com.tw.` |

> **提示**：如果 DNS 管理介面是在 zone 內操作（例如 `example.edu.tw` zone），名稱欄位可填相對名稱（如 `_acme-challenge.hylib`），系統會自動補上 zone 名稱。

### 2. 注意：目標值結尾的 `.` 不能省略

目標值最後的 `.`（英文句點）代表完整網域名稱（FQDN）。**如果省略，DNS 會自動附加 zone name，導致解析錯誤。**

各 DNS 系統的填寫方式：

| DNS 系統 | 目標值結尾的 `.` | 說明 |
|---|---|---|
| BIND (zone file) | **必須加** | 例如 `...acme.k00.com.tw.` |
| Windows DNS Manager | **必須加** | 在 FQDN 欄位填入完整值，含結尾的點 |
| Cloudflare / AWS Route53 | **不用加** | 這些系統會自動處理 |

如不確定，**建議加上結尾的 `.` 較為安全**。

### 3. 驗證設定

設定完成後，執行以下指令確認（將域名替換為實際值）：

```
nslookup -type=CNAME _acme-challenge.【客戶域名】
```

**正確結果：**

```
_acme-challenge.hylib.example.edu.tw  canonical name = _acme-challenge.hylib.example.edu.tw.acme.k00.com.tw.
```

**錯誤結果（缺少結尾 `.` 導致）：**

```
_acme-challenge.hylib.example.edu.tw  canonical name = _acme-challenge.hylib.example.edu.tw.acme.k00.com.tw.example.edu.tw.
```

若目標值後面多出了 zone name，請在目標值結尾補上 `.` 後重新設定。

---

## 效益

| | 設定前（手動） | 設定後（自動） |
|---|---|---|
| 每次續約 | 需人工加／刪 TXT 記錄 | 全自動，無需配合 |
| 作業時間 | 需協調等待 | 零 |
| 漏約風險 | 有 | 無 |

---

## 安全說明

- `_acme-challenge` 為 ACME 協議（RFC 8555）標準前綴，專用於 SSL 憑證域名驗證
- 影響範圍僅限 `_acme-challenge` 此一特定前綴，**網站、Email、其他 DNS 記錄完全不受影響**
- 此 CNAME 僅將驗證流程委派至指定的 DNS，不改變任何現有服務的流量
- 如需停用自動化，移除對應的 CNAME 記錄即可

