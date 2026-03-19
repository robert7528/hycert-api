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
