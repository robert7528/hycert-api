package agent

import (
	"time"

	"gorm.io/gorm"
)

// ── Agent Token (admin DB) ──────────────────────────────────────────────────

func (AgentToken) TableName() string { return "hycert_agent_tokens" }

type AgentToken struct {
	ID             uint           `gorm:"primaryKey" json:"id"`
	Name           string         `gorm:"not null" json:"name"`
	TokenHash      string         `gorm:"not null;uniqueIndex" json:"-"`
	TokenPrefix    string         `gorm:"not null" json:"token_prefix"` // 前 8 碼
	TokenEncrypted string         `gorm:"not null;default:''" json:"-"` // Tink 加密明文
	Label          string         `gorm:"not null;default:''" json:"label"`
	TenantCode     string         `gorm:"not null" json:"tenant_code"`
	AllowedHosts   string         `gorm:"column:allowed_hosts;type:jsonb;default:'[]'" json:"allowed_hosts"`
	LastUsedAt     *time.Time     `json:"last_used_at"`
	ExpiresAt      *time.Time     `json:"expires_at"`
	Status         string         `gorm:"default:'active'" json:"status"` // active / revoked
	CreatedBy      string         `json:"created_by"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

// AgentTokenDTO is the API response (no hash).
type AgentTokenDTO struct {
	ID           uint       `json:"id"`
	Name         string     `json:"name"`
	TokenPrefix  string     `json:"token_prefix"`
	Label        string     `json:"label"`
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
		Label:        t.Label,
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
	Label        string   `json:"label,omitempty"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	ExpiresAt    *string  `json:"expires_at,omitempty"` // RFC3339
}

type UpdateTokenRequest struct {
	Name  *string `json:"name,omitempty"`
	Label *string `json:"label,omitempty"`
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
	AgentID         string  `json:"agent_id,omitempty"`
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

// ── Agent Registration (tenant DB) ───────────────────────────────────────────

func (AgentRegistration) TableName() string { return "hycert_agent_registrations" }

type AgentRegistration struct {
	ID           uint           `gorm:"primaryKey" json:"id"`
	AgentID      string         `gorm:"not null;uniqueIndex" json:"agent_id"`
	AgentTokenID uint           `gorm:"not null" json:"agent_token_id"`
	Name         string         `gorm:"not null;default:''" json:"name"`
	Hostname     string         `gorm:"not null;default:''" json:"hostname"`
	IPAddresses  string         `gorm:"type:jsonb;default:'[]'" json:"ip_addresses"`
	OS           string         `gorm:"default:''" json:"os"`
	Version      string         `gorm:"default:''" json:"version"`
	PollInterval int            `gorm:"column:poll_interval;default:3600" json:"poll_interval"`
	Status       string         `gorm:"default:'active'" json:"status"`
	LastSeenAt   *time.Time     `json:"last_seen_at"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
}

type AgentRegistrationDTO struct {
	ID           uint       `json:"id"`
	AgentID      string     `json:"agent_id"`
	AgentTokenID uint       `json:"agent_token_id"`
	Name         string     `json:"name"`
	Hostname     string     `json:"hostname"`
	IPAddresses  string     `json:"ip_addresses"`
	OS           string     `json:"os"`
	Version      string     `json:"version"`
	PollInterval int        `json:"poll_interval"`
	Status       string     `json:"status"`
	LastSeenAt   *time.Time `json:"last_seen_at"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (r *AgentRegistration) ToDTO() AgentRegistrationDTO {
	return AgentRegistrationDTO{
		ID:           r.ID,
		AgentID:      r.AgentID,
		AgentTokenID: r.AgentTokenID,
		Name:         r.Name,
		Hostname:     r.Hostname,
		IPAddresses:  r.IPAddresses,
		OS:           r.OS,
		Version:      r.Version,
		PollInterval: r.PollInterval,
		Status:       r.Status,
		LastSeenAt:   r.LastSeenAt,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}

type RegisterAgentRequest struct {
	AgentID     string   `json:"agent_id" binding:"required"`
	Name        string   `json:"name"`
	Hostname    string   `json:"hostname"`
	IPAddresses []string `json:"ip_addresses,omitempty"`
	OS          string   `json:"os,omitempty"`
	Version     string   `json:"version,omitempty"`
	Interval    int      `json:"interval,omitempty"`
}

type AgentRegistrationListQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Status   string `form:"status"`
}

type AgentRegistrationListResponse struct {
	Items      []AgentRegistrationDTO `json:"items"`
	Total      int64                  `json:"total"`
	Page       int                    `json:"page"`
	PageSize   int                    `json:"page_size"`
	TotalPages int                    `json:"total_pages"`
}
