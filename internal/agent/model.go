package agent

import (
	"time"

	"gorm.io/gorm"
)

// ── Agent Token (admin DB) ──────────────────────────────────────────────────

func (AgentToken) TableName() string { return "hycert_agent_tokens" }

type AgentToken struct {
	ID          uint           `gorm:"primaryKey" json:"id"`
	Name        string         `gorm:"not null" json:"name"`
	TokenHash   string         `gorm:"not null;uniqueIndex" json:"-"`
	TokenPrefix string         `gorm:"not null" json:"token_prefix"` // 前 8 碼
	TenantCode  string         `gorm:"not null" json:"tenant_code"`
	AllowedHosts string        `gorm:"column:allowed_hosts;type:jsonb;default:'[]'" json:"allowed_hosts"`
	LastUsedAt  *time.Time     `json:"last_used_at"`
	ExpiresAt   *time.Time     `json:"expires_at"`
	Status      string         `gorm:"default:'active'" json:"status"` // active / revoked
	CreatedBy   string         `json:"created_by"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// AgentTokenDTO is the API response (no hash).
type AgentTokenDTO struct {
	ID           uint       `json:"id"`
	Name         string     `json:"name"`
	TokenPrefix  string     `json:"token_prefix"`
	TenantCode   string     `json:"tenant_code"`
	AllowedHosts string     `json:"allowed_hosts"`
	LastUsedAt   *time.Time `json:"last_used_at"`
	ExpiresAt    *time.Time `json:"expires_at"`
	Status       string     `json:"status"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
}

func (t *AgentToken) ToDTO() AgentTokenDTO {
	return AgentTokenDTO{
		ID:           t.ID,
		Name:         t.Name,
		TokenPrefix:  t.TokenPrefix,
		TenantCode:   t.TenantCode,
		AllowedHosts: t.AllowedHosts,
		LastUsedAt:   t.LastUsedAt,
		ExpiresAt:    t.ExpiresAt,
		Status:       t.Status,
		CreatedBy:    t.CreatedBy,
		CreatedAt:    t.CreatedAt,
	}
}

// ── Deployment History (tenant DB) ──────────────────────────────────────────

func (DeploymentHistory) TableName() string { return "hycert_deployment_history" }

type DeploymentHistory struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	DeploymentID  uint      `gorm:"not null" json:"deployment_id"`
	CertificateID uint     `gorm:"not null" json:"certificate_id"`
	AgentTokenID  *uint     `json:"agent_token_id"`
	Fingerprint   string    `json:"fingerprint"`
	Action        string    `gorm:"not null" json:"action"` // deploy / rollback / verify
	Status        string    `gorm:"not null" json:"status"` // success / failed
	ErrorMessage  string    `gorm:"type:text" json:"error_message,omitempty"`
	DurationMs    *int      `json:"duration_ms,omitempty"`
	DeployedAt    time.Time `gorm:"not null" json:"deployed_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// ── Request/Response DTOs ───────────────────────────────────────────────────

type CreateTokenRequest struct {
	Name         string   `json:"name" binding:"required"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	ExpiresAt    *string  `json:"expires_at,omitempty"` // RFC3339
}

type CreateTokenResponse struct {
	Token string        `json:"token"` // 明文，只顯示一次
	AgentTokenDTO
}

type TokenListQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Status   string `form:"status"`
}

type TokenListResponse struct {
	Items      []AgentTokenDTO `json:"items"`
	Total      int64           `json:"total"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
	TotalPages int             `json:"total_pages"`
}

// ── Agent API DTOs ──────────────────────────────────────────────────────────

type AgentDeploymentDTO struct {
	ID            uint       `json:"id"`
	CertificateID uint      `json:"certificate_id"`
	TargetHost    string     `json:"target_host"`
	TargetService string    `json:"target_service"`
	TargetDetail  string     `json:"target_detail"`
	Port          *int       `json:"port"`
	DeployStatus  string     `json:"deploy_status"`
	LastFingerprint string  `json:"last_fingerprint"`
	CertFingerprint string  `json:"cert_fingerprint"` // 目前憑證的 fingerprint（用於比對）
}

type UpdateDeployStatusRequest struct {
	Action       string `json:"action" binding:"required"`       // deploy / rollback / verify
	Status       string `json:"status" binding:"required"`       // success / failed
	Fingerprint  string `json:"fingerprint,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	DurationMs   *int   `json:"duration_ms,omitempty"`
}

type HistoryListQuery struct {
	Page     int `form:"page,default=1"`
	PageSize int `form:"page_size,default=20"`
}

type HistoryListResponse struct {
	Items      []DeploymentHistory `json:"items"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page"`
	PageSize   int                 `json:"page_size"`
	TotalPages int                 `json:"total_pages"`
}
