package csr

import (
	"time"

	"gorm.io/gorm"
)

func (CSR) TableName() string { return "hycert_csrs" }

type CSR struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	CommonName    string         `gorm:"not null" json:"common_name"`
	SANs          string         `gorm:"type:jsonb" json:"sans"`
	Subject       string         `gorm:"type:jsonb" json:"subject"`          // {o, ou, c, st, l}
	KeyAlgorithm  string         `json:"key_algorithm"`
	KeyBits       int            `json:"key_bits"`
	CSRPEM        string         `gorm:"type:text;not null" json:"-"`
	PrivateKeyEnc string         `gorm:"type:text;not null" json:"-"`        // Tink-encrypted
	Status        string         `gorm:"default:'pending';index" json:"status"` // pending / signed
	CertificateID *uint          `json:"certificate_id"`                     // signed → linked cert
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}

// CSRDTO is the API response representation (no encrypted fields).
type CSRDTO struct {
	ID            uint      `json:"id"`
	CommonName    string    `json:"common_name"`
	SANs          string    `json:"sans"`
	Subject       string    `json:"subject"`
	KeyAlgorithm  string    `json:"key_algorithm"`
	KeyBits       int       `json:"key_bits"`
	HasPrivateKey bool      `json:"has_private_key"`
	Status        string    `json:"status"`
	CertificateID *uint     `json:"certificate_id"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ToDTO converts a CSR entity to its API representation.
func (c *CSR) ToDTO() CSRDTO {
	return CSRDTO{
		ID:            c.ID,
		CommonName:    c.CommonName,
		SANs:          c.SANs,
		Subject:       c.Subject,
		KeyAlgorithm:  c.KeyAlgorithm,
		KeyBits:       c.KeyBits,
		HasPrivateKey: c.PrivateKeyEnc != "",
		Status:        c.Status,
		CertificateID: c.CertificateID,
		CreatedBy:     c.CreatedBy,
		CreatedAt:     c.CreatedAt,
		UpdatedAt:     c.UpdatedAt,
	}
}

// CreateCSRRequest is the payload for generating a new CSR.
type CreateCSRRequest struct {
	Domain  string   `json:"domain" binding:"required"`
	SANs    []string `json:"sans,omitempty"`
	Subject struct {
		O  string `json:"o,omitempty"`
		OU string `json:"ou,omitempty"`
		C  string `json:"c,omitempty"`
		ST string `json:"st,omitempty"`
		L  string `json:"l,omitempty"`
	} `json:"subject,omitempty"`
	KeyType string `json:"key_type,omitempty"` // RSA (default) | EC
	KeyBits int    `json:"key_bits,omitempty"` // RSA: 2048/4096, EC: 256/384
}

// CSRListQuery captures query parameters for listing CSRs.
type CSRListQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Status   string `form:"status"`
}

// CSRListResponse wraps a paginated list of CSRs.
type CSRListResponse struct {
	Items      []CSRDTO `json:"items"`
	Total      int64    `json:"total"`
	Page       int      `json:"page"`
	PageSize   int      `json:"page_size"`
	TotalPages int      `json:"total_pages"`
}
