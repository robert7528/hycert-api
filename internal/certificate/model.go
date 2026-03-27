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
	SANs              string         `gorm:"column:sans;type:jsonb" json:"sans"`     // JSON array: ["*.example.com"]
	SerialNumber      string         `json:"serial_number"`
	IssuerCN          string         `json:"issuer_cn"`
	NotBefore         *time.Time     `json:"not_before"`
	NotAfter          *time.Time     `json:"not_after"`
	KeyAlgorithm      string         `json:"key_algorithm"`                         // RSA 2048 / EC P-256
	FingerprintSHA256 string         `gorm:"column:fingerprint_sha256;index" json:"fingerprint_sha256"`
	Status            string         `gorm:"default:'active';index" json:"status"`  // active / expired / revoked
	Source            string         `gorm:"default:'manual'" json:"source"`        // manual / csr / acme
	CertPEM           string         `gorm:"column:cert_pem;type:text;not null" json:"-"` // cert + chain PEM
	PrivateKeyEnc     string         `gorm:"type:text" json:"-"`                    // Tink-encrypted private key
	KeyEncrypted      bool           `gorm:"default:false" json:"key_encrypted"`    // original key had passphrase
	CSRID             *uint          `gorm:"column:csr_id" json:"csr_id"`           // FK → hycert_csrs
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

// ToDTO converts a Certificate entity to its API representation.
func (c *Certificate) ToDTO() CertificateDTO {
	return CertificateDTO{
		ID:                c.ID,
		Name:              c.Name,
		CommonName:        c.CommonName,
		SANs:              c.SANs,
		SerialNumber:      c.SerialNumber,
		IssuerCN:          c.IssuerCN,
		NotBefore:         c.NotBefore,
		NotAfter:          c.NotAfter,
		KeyAlgorithm:      c.KeyAlgorithm,
		FingerprintSHA256: c.FingerprintSHA256,
		Status:            c.Status,
		Source:            c.Source,
		HasPrivateKey:     c.PrivateKeyEnc != "",
		KeyEncrypted:      c.KeyEncrypted,
		CSRID:             c.CSRID,
		Tags:              c.Tags,
		Notes:             c.Notes,
		CreatedBy:         c.CreatedBy,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}
}

// ImportRequest is the payload for importing a certificate.
type ImportRequest struct {
	Certificate string `json:"certificate" binding:"required"` // PEM or base64-encoded binary
	PrivateKey  string `json:"private_key,omitempty"`
	InputType   string `json:"input_type,omitempty"`   // auto | pem | der_base64 | pfx_base64 | jks_base64
	Password    string `json:"password,omitempty"`     // for PFX/JKS input
	Name        string `json:"name,omitempty"`         // user-defined display name
	Tags        string `json:"tags,omitempty"`         // JSON array
	Notes       string `json:"notes,omitempty"`
	Source      string `json:"source,omitempty"`       // manual | acme (default: manual)
}

// UpdateRequest is the payload for updating certificate metadata.
type UpdateRequest struct {
	Name  *string `json:"name,omitempty"`
	Tags  *string `json:"tags,omitempty"`
	Notes *string `json:"notes,omitempty"`
}

// UploadKeyRequest is the payload for supplementing a private key to an existing certificate.
type UploadKeyRequest struct {
	PrivateKey string `json:"private_key" binding:"required"`
	Password   string `json:"password,omitempty"` // if the key is encrypted
}

// ListQuery captures query parameters for listing certificates.
type ListQuery struct {
	Page     int    `form:"page,default=1"`
	PageSize int    `form:"page_size,default=20"`
	Status   string `form:"status"`
	Search   string `form:"search"`           // CN or SAN substring
	ExpireIn int    `form:"expire_in"`         // days until expiry (filter certs expiring within N days)
	SortBy   string `form:"sort_by,default=created_at"`
	SortDir  string `form:"sort_dir,default=desc"`
}

// DownloadQuery captures query parameters for downloading a certificate.
type DownloadQuery struct {
	Format       string `form:"format,default=pem"` // pem | key | pfx | jks | der
	Password     string `form:"password"`           // required for pfx/jks
	Alias        string `form:"alias"`              // JKS key alias (default: "1")
	IncludeChain *bool  `form:"include_chain"`
	IncludeKey   bool   `form:"include_key"`        // for pem: merge private key into PEM (HAProxy)
}

// ListResponse wraps a paginated list of certificates.
type ListResponse struct {
	Items      []CertificateDTO `json:"items"`
	Total      int64            `json:"total"`
	Page       int              `json:"page"`
	PageSize   int              `json:"page_size"`
	TotalPages int              `json:"total_pages"`
}
