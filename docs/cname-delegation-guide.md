# SSL 憑證自動續約 — CNAME 委派設定指南

hycert 系統 · CNAME 委派驗證

---

## 主旨

SSL 憑證續約流程升級 — 請協助新增 DNS 設定（一次性）

## 說明

【聯絡人】 您好，

感謝【客戶名稱】長期使用我們的 SSL 憑證管理服務。

目前憑證續約需要每次人工配合新增 DNS 記錄。為了減少貴單位的作業負擔，我們已完成自動化續約系統建置，**只需要請貴單位配合一次性設定，之後憑證續約將完全自動進行，不再需要人工配合。**

---

## 請新增以下 DNS 記錄

請針對每個需要自動化的域名，新增一筆 CNAME 記錄：

| 欄位 | 內容 |
|---|---|
| 類型 | CNAME |
| 名稱 | `_acme-challenge.【客戶域名】` |
| 值 | `_acme-challenge.【客戶域名】.acme.k00.com.tw.` |
| TTL | 預設值即可（或填 3600） |

### 實際設定值

| 名稱（Name） | 類型 | 目標值（Value） |
|---|---|---|
| `_acme-challenge.【客戶域名1】` | CNAME | `_acme-challenge.【客戶域名1】.acme.k00.com.tw.` |
| `_acme-challenge.【客戶域名2】` | CNAME | `_acme-challenge.【客戶域名2】.acme.k00.com.tw.` |

> **提示**：如果貴單位的 DNS 管理介面是在 zone 內操作（例如 `example.edu.tw` zone），名稱欄位可填相對名稱（如 `_acme-challenge.hylib`），系統會自動補上 zone 名稱。

---

## 重要：目標值結尾的 `.` 不能省略

目標值最後的 `.`（英文句點）代表這是一個完整的網域名稱（FQDN）。

**如果省略，DNS 系統會自動在後面附加 zone name，導致解析錯誤。**

### 各 DNS 系統的填寫方式

| DNS 系統 | 目標值結尾的 `.` | 說明 |
|---|---|---|
| BIND (zone file) | **必須加** | 例如 `_acme-challenge.xxx.acme.example.com.` |
| Windows DNS Manager | **必須加** | 在 FQDN 欄位填入完整值，含結尾的點 |
| Cloudflare / AWS Route53 | **不用加** | 這些系統會自動處理 |

如不確定貴單位 DNS 系統的行為，**建議加上結尾的 `.` 較為安全**。

---

## 驗證方式

設定完成後，請執行以下指令確認是否正確（將域名替換為實際值）：

```
nslookup -type=CNAME _acme-challenge.【客戶域名】
```

### 正確結果

```
_acme-challenge.hylib.example.edu.tw  canonical name = _acme-challenge.hylib.example.edu.tw.acme.example.com.
```

### 錯誤結果（缺少結尾的 `.` 導致）

```
_acme-challenge.hylib.example.edu.tw  canonical name = _acme-challenge.hylib.example.edu.tw.acme.example.com.example.edu.tw.
```

若出現此結果（目標值後面多出了 zone name），請在目標值結尾補上 `.` 後重新設定。

---

## 設定完成後的效益

| | 目前（手動） | 設定後（自動） |
|---|---|---|
| 每次續約 | 需人工加／刪 TXT 記錄 | 全自動，無需配合 |
| 作業時間 | 需協調等待 | 零 |
| 漏約風險 | 有 | 無 |

---

## 技術與安全說明

- `_acme-challenge` 為 ACME 協議（RFC 8555）標準前綴，專用於 SSL 憑證域名驗證
- 此 CNAME 將驗證流程委派至我方管理的 DNS，不影響貴單位任何現有服務
- 影響範圍僅限 `_acme-challenge.【客戶域名】` 此一特定前綴，網站、Email、其他記錄完全不受影響
- 設定後即為長期有效，憑證到期時系統會自動使用此 CNAME 進行續約驗證
- 如需停用自動化，移除對應的 CNAME 記錄即可

---

## 設定完成後

1. 請回信或來電通知我們
2. 我們會測試確認設定正確
3. 後續憑證續約將完全自動進行

聯絡資訊：
- 信箱：【我方聯絡信箱】
- 電話：【我方聯絡電話】

謝謝貴單位的配合！

【我方公司名稱】 敬上

---

## 變數對照表（內部使用，發送前刪除此段）

| 變數 | 說明 | 範例 |
|---|---|---|
| 【客戶域名】 | 客戶的網域名稱 | hylib.ntus.edu.tw |
| 【客戶名稱】 | 客戶公司／單位名稱 | XX 大學 / XX 公司 |
| 【聯絡人】 | 收件人稱謂 | 王先生 / 您 |
| 【我方公司名稱】 | 公司名稱 | XX 資訊股份有限公司 |
| 【我方聯絡信箱】 | 客服或業務信箱 | support@example.com |
| 【我方聯絡電話】 | 客服或業務電話 | 02-xxxx-xxxx |

> **注意**：發送前請確認所有【】變數已替換為實際內容，並確認客戶域名與 CNAME 值完全正確。
