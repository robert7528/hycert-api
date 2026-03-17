package utility

import (
	"time"

	"github.com/hysp/hycert-api/internal/chain"
)

// ── Verify ──────────────────────────────────────────────────────────────────

type VerifyRequest struct {
	Certificate string     `json:"certificate" binding:"required"`
	PrivateKey  string     `json:"private_key,omitempty"`
	InputType   string     `json:"input_type,omitempty"`   // auto | pem | der_base64 | pfx_base64
	Password    string     `json:"password,omitempty"`
	ChainInput  ChainInput `json:"chain_input,omitempty"`
	Options     struct {
		CheckOCSP bool `json:"check_ocsp"`
		CheckCRL  bool `json:"check_crl"`
	} `json:"options,omitempty"`
}

type ChainInput struct {
	Intermediates []string `json:"intermediates,omitempty"`
	Root          string   `json:"root,omitempty"`
	Bundle        string   `json:"bundle,omitempty"`
}

type VerifyResponse struct {
	Subject     SubjectInfo     `json:"subject"`
	Issuer      IssuerInfo      `json:"issuer"`
	Validity    ValidityInfo    `json:"validity"`
	SANs        SANInfo         `json:"sans"`
	KeyInfo     KeyInfoResp     `json:"key_info"`
	Fingerprint FingerprintInfo `json:"fingerprint"`
	Checks      ChecksInfo      `json:"checks"`
	Chain       []ChainNode     `json:"chain"`
	Warnings    []chain.Warning  `json:"warnings,omitempty"`
}

type SubjectInfo struct {
	CN string `json:"cn"`
	O  string `json:"o,omitempty"`
	C  string `json:"c,omitempty"`
	OU string `json:"ou,omitempty"`
}

type IssuerInfo struct {
	CN string `json:"cn"`
	O  string `json:"o,omitempty"`
}

type ValidityInfo struct {
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	IsExpired     bool      `json:"is_expired"`
}

type SANInfo struct {
	DNS []string `json:"dns"`
	IP  []string `json:"ip"`
}

type KeyInfoResp struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits"`
}

type FingerprintInfo struct {
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
}

type ChecksInfo struct {
	KeyPairMatch  *bool  `json:"key_pair_match"`
	ChainValid    bool   `json:"chain_valid"`
	ChainComplete bool   `json:"chain_complete"`
	RootTrusted   bool   `json:"root_trusted"`
	RootSource    string `json:"root_source,omitempty"`
	OCSPStatus    string `json:"ocsp_status,omitempty"`
	CRLRevoked    *bool  `json:"crl_revoked,omitempty"`
}

type ChainNode struct {
	Index    int    `json:"index"`
	Role     string `json:"role"`
	CN       string `json:"cn"`
	IssuerCN string `json:"issuer_cn"`
	Source   string `json:"source"`
}

// Warning is re-exported from chain package to avoid circular imports.
// Use chain.Warning directly where possible.

// ── Parse ───────────────────────────────────────────────────────────────────

type ParseRequest struct {
	Input     string `json:"input" binding:"required"`
	InputType string `json:"input_type,omitempty"` // auto | pem | der_base64 | pfx_base64
	Password  string `json:"password,omitempty"`
}

type ParseResponse struct {
	Format       string       `json:"format"`
	Certificates []CertDetail `json:"certificates"`
	HasKey       bool         `json:"has_private_key"`
}

type CertDetail struct {
	Subject            SubjectInfo     `json:"subject"`
	Issuer             IssuerInfo      `json:"issuer"`
	SerialNumber       string          `json:"serial_number"`
	Validity           ValidityInfo    `json:"validity"`
	SANs               SANInfo         `json:"sans"`
	KeyInfo            KeyInfoResp     `json:"key_info"`
	SignatureAlgorithm string          `json:"signature_algorithm"`
	Fingerprint        FingerprintInfo `json:"fingerprint"`
	IsCA               bool            `json:"is_ca"`
	Role               string          `json:"role"` // leaf | intermediate | root
}

// ── Convert ─────────────────────────────────────────────────────────────────

type ConvertRequest struct {
	Certificate   string     `json:"certificate" binding:"required"`
	PrivateKey    string     `json:"private_key,omitempty"`
	InputType     string     `json:"input_type,omitempty"`     // auto | pem | der_base64 | pfx_base64
	InputPassword string     `json:"input_password,omitempty"` // password for input PFX (separate from output password)
	ChainInput    ChainInput `json:"chain_input,omitempty"`
	TargetFormat  string     `json:"target_format" binding:"required"` // pem | der | pfx | jks | p7b
	Options       struct {
		Password     string `json:"password,omitempty"`
		IncludeChain *bool  `json:"include_chain,omitempty"`
		FriendlyName string `json:"friendly_name,omitempty"`
	} `json:"options,omitempty"`
}

type ConvertResponse struct {
	Format           string `json:"format"`
	ContentBase64    string `json:"content_base64"`
	FilenameSugg     string `json:"filename_suggestion"`
	ChainIncluded    bool   `json:"chain_included"`
	ChainNodes       int    `json:"chain_nodes"`
}

// ── Generate CSR ────────────────────────────────────────────────────────────

type GenerateCSRRequest struct {
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
	KeyBits int    `json:"key_bits,omitempty"` // RSA: 2048(default)/4096, EC: 256(default)/384
}

type GenerateCSRResponse struct {
	CSRPEM        string `json:"csr_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
	KeyType       string `json:"key_type"`
	KeyBits       int    `json:"key_bits"`
	Warning       string `json:"warning"`
}
