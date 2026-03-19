package certificate

import (
	"time"

	"gorm.io/gorm"
)

func (Certificate) TableName() string { return "hycert_certificates" }

type Certificate struct {
	ID                uint           `gorm:"primaryKey" json:"id"`
	Name              string         `gorm:"not null" json:"name"`
	CommonName        string         `gorm:"not null" json:"common_name"`
	SANs              string         `gorm:"type:jsonb" json:"sans"`                // JSON array: ["*.example.com"]
	SerialNumber      string         `json:"serial_number"`
	IssuerCN          string         `json:"issuer_cn"`
	NotBefore         *time.Time     `json:"not_before"`
	NotAfter          *time.Time     `json:"not_after"`
	KeyAlgorithm      string         `json:"key_algorithm"`                         // RSA 2048 / EC P-256
	FingerprintSHA256 string         `gorm:"index" json:"fingerprint_sha256"`
	Status            string         `gorm:"default:'active';index" json:"status"`  // active / expired / revoked
	Source            string         `gorm:"default:'manual'" json:"source"`        // manual / csr / acme
	CertPEM           string         `gorm:"type:text;not null" json:"-"`           // cert + chain PEM
	PrivateKeyEnc     string         `gorm:"type:text" json:"-"`                    // Tink-encrypted private key
	KeyEncrypted      bool           `gorm:"default:false" json:"key_encrypted"`    // original key had passphrase
	CSRID             *uint          `json:"csr_id"`                                // FK → hycert_csrs
	Tags              string         `gorm:"type:jsonb;default:'[]'" json:"tags"`   // JSON array
	Notes             string         `gorm:"type:text" json:"notes"`
	CreatedBy         string         `json:"created_by"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	DeletedAt         gorm.DeletedAt `gorm:"index" json:"-"`
}

// CertificateDTO is the API response representation (no encrypted fields).
type CertificateDTO struct {
	ID                uint       `json:"id"`
	Name              string     `json:"name"`
	CommonName        string     `json:"common_name"`
	SANs              string     `json:"sans"`
	SerialNumber      string     `json:"serial_number"`
	IssuerCN          string     `json:"issuer_cn"`
	NotBefore         *time.Time `json:"not_before"`
	NotAfter          *time.Time `json:"not_after"`
	KeyAlgorithm      string     `json:"key_algorithm"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	Status            string     `json:"status"`
	Source            string     `json:"source"`
	HasPrivateKey     bool       `json:"has_private_key"`
	KeyEncrypted      bool       `json:"key_encrypted"`
	CSRID             *uint      `json:"csr_id"`
	Tags              string     `json:"tags"`
	Notes             string     `json:"notes"`
	CreatedBy         string     `json:"created_by"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}
