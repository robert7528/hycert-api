package acme

import (
	"time"

	"gorm.io/gorm"
)

// ── ACME Account (tenant DB) ────────────────────────────────────────────────

func (AcmeAccount) TableName() string { return "hycert_acme_accounts" }

type AcmeAccount struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	Name          string         `gorm:"not null" json:"name"`
	Email         string         `gorm:"not null" json:"email"`
	DirectoryURL  string         `gorm:"column:directory_url;not null" json:"directory_url"`
	PrivateKeyEnc string         `gorm:"column:private_key_enc;type:text;not null" json:"-"`
	Registration  string         `gorm:"type:jsonb" json:"registration"`
	Status        string         `gorm:"default:'active'" json:"status"` // active / inactive
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

type AcmeAccountDTO struct {
	ID           uint      `json:"id"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	DirectoryURL string    `json:"directory_url"`
	Registration string    `json:"registration"`
	Status       string    `json:"status"`
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (a *AcmeAccount) ToDTO() AcmeAccountDTO {
	return AcmeAccountDTO{
		ID:           a.ID,
		Name:         a.Name,
		Email:        a.Email,
		DirectoryURL: a.DirectoryURL,
		Registration: a.Registration,
		Status:       a.Status,
		CreatedBy:    a.CreatedBy,
		CreatedAt:    a.CreatedAt,
		UpdatedAt:    a.UpdatedAt,
	}
}

// ── ACME Order (tenant DB) ──────────────────────────────────────────────────

func (AcmeOrder) TableName() string { return "hycert_acme_orders" }

type AcmeOrder struct {
	ID              uint           `gorm:"primaryKey" json:"id"`
	AccountID       uint           `gorm:"not null" json:"account_id"`
	CertificateID   *uint          `json:"certificate_id"`
	Domains         string         `gorm:"type:jsonb;not null" json:"domains"`
	ChallengeType   string         `gorm:"column:challenge_type;not null" json:"challenge_type"` // dns-01 / http-01
	DNSProvider     string         `gorm:"column:dns_provider" json:"dns_provider"`              // cloudflare / manual
	DNSConfigEnc    string         `gorm:"column:dns_config_enc;type:text" json:"-"`
	KeyType         string         `gorm:"default:'ec256'" json:"key_type"` // ec256 / ec384 / rsa2048 / rsa4096
	Status          string         `gorm:"default:'pending'" json:"status"` // pending / processing / valid / failed / cancelled
	ErrorMessage    string         `gorm:"type:text" json:"error_message,omitempty"`
	OrderURL        string         `gorm:"column:order_url" json:"order_url,omitempty"`
	RenewFromID     *uint          `gorm:"column:renew_from_id" json:"renew_from_id"`
	AutoRenew       bool           `gorm:"default:true" json:"auto_renew"`
	RenewBeforeDays int            `gorm:"default:30" json:"renew_before_days"`
	LastRenewedAt   *time.Time     `json:"last_renewed_at"`
	RequestedBy     string         `json:"requested_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

type AcmeOrderDTO struct {
	ID              uint       `json:"id"`
	AccountID       uint       `json:"account_id"`
	CertificateID   *uint      `json:"certificate_id"`
	Domains         string     `json:"domains"`
	ChallengeType   string     `json:"challenge_type"`
	DNSProvider     string     `json:"dns_provider"`
	KeyType         string     `json:"key_type"`
	Status          string     `json:"status"`
	ErrorMessage    string     `json:"error_message,omitempty"`
	OrderURL        string     `json:"order_url,omitempty"`
	RenewFromID     *uint      `json:"renew_from_id"`
	AutoRenew       bool       `json:"auto_renew"`
	RenewBeforeDays int        `json:"renew_before_days"`
	LastRenewedAt   *time.Time `json:"last_renewed_at"`
	RequestedBy     string     `json:"requested_by"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

func (o *AcmeOrder) ToDTO() AcmeOrderDTO {
	return AcmeOrderDTO{
		ID:              o.ID,
		AccountID:       o.AccountID,
		CertificateID:   o.CertificateID,
		Domains:         o.Domains,
		ChallengeType:   o.ChallengeType,
		DNSProvider:     o.DNSProvider,
		KeyType:         o.KeyType,
		Status:          o.Status,
		ErrorMessage:    o.ErrorMessage,
		OrderURL:        o.OrderURL,
		RenewFromID:     o.RenewFromID,
		AutoRenew:       o.AutoRenew,
		RenewBeforeDays: o.RenewBeforeDays,
		LastRenewedAt:   o.LastRenewedAt,
		RequestedBy:     o.RequestedBy,
		CreatedAt:       o.CreatedAt,
		UpdatedAt:       o.UpdatedAt,
	}
}

// ── Request/Response DTOs ───────────────────────────────────────────────────

type CreateAccountRequest struct {
	Name         string `json:"name" binding:"required"`
	Email        string `json:"email" binding:"required"`
	DirectoryURL string `json:"directory_url" binding:"required"` // e.g. https://acme-v02.api.letsencrypt.org/directory
}

type UpdateAccountRequest struct {
	Name   *string `json:"name,omitempty"`
	Email  *string `json:"email,omitempty"`
	Status *string `json:"status,omitempty"`
}

type AccountListQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Status   string `form:"status"`
}

type AccountListResponse struct {
	Items      []AcmeAccountDTO `json:"items"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}

type CreateOrderRequest struct {
	AccountID       uint     `json:"account_id" binding:"required"`
	Domains         []string `json:"domains" binding:"required"`
	ChallengeType   string   `json:"challenge_type" binding:"required"` // dns-01 / http-01
	DNSProvider     string   `json:"dns_provider,omitempty"`            // cloudflare / manual
	DNSConfig       string   `json:"dns_config,omitempty"`              // JSON credentials (will be Tink-encrypted)
	KeyType         string   `json:"key_type,omitempty"`                // ec256 / ec384 / rsa2048 / rsa4096
	AutoRenew       *bool    `json:"auto_renew,omitempty"`
	RenewBeforeDays *int     `json:"renew_before_days,omitempty"`
}

type OrderListQuery struct {
	Page      int    `form:"page,default=1"`
	PageSize  int    `form:"page_size,default=20"`
	AccountID uint   `form:"account_id"`
	Status    string `form:"status"`
}

type OrderListResponse struct {
	Items      []AcmeOrderDTO `json:"items"`
	Total      int64          `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}
