package certificate

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hysp/hycert-api/internal/chain"
	"github.com/hysp/hycert-api/internal/converter"
	"github.com/hysp/hycert-api/internal/parser"
	"github.com/robert7528/hycore/crypto"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Service handles certificate business logic.
type Service struct {
	repo      *Repository
	parser    *parser.Parser
	builder   *chain.Builder
	converter *converter.Converter
	enc       crypto.Encryptor
	log       *zap.Logger
}

// NewService creates a new certificate Service.
func NewService(
	repo *Repository,
	p *parser.Parser,
	b *chain.Builder,
	conv *converter.Converter,
	enc crypto.Encryptor,
	log *zap.Logger,
) *Service {
	return &Service{
		repo:      repo,
		parser:    p,
		builder:   b,
		converter: conv,
		enc:       enc,
		log:       log,
	}
}

// ImportResult is the result of an import operation.
type ImportResult struct {
	Certificate CertificateDTO  `json:"certificate"`
	Warnings    []chain.Warning `json:"warnings,omitempty"`
}

// Import parses, validates, and stores a certificate.
func (s *Service) Import(db *gorm.DB, req *ImportRequest, username string) (*ImportResult, error) {
	// 1. Parse input
	result, err := s.parser.ParseWithType([]byte(req.Certificate), req.InputType, req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	if len(result.Certificates) == 0 {
		return nil, fmt.Errorf("no certificate found in input")
	}

	leaf := result.Certificates[0]

	// 2. Extract metadata
	cn := leaf.Subject.CommonName
	serial := leaf.SerialNumber.Text(16)
	issuerCN := leaf.Issuer.CommonName
	keyAlgo := describeKeyAlgorithm(leaf)
	fingerprint := computeSHA256Fingerprint(leaf)

	sans, _ := json.Marshal(extractSANsList(leaf))

	// 3. Check duplicate by fingerprint
	existing, err := s.repo.FindByFingerprint(db, fingerprint)
	if err == nil && existing != nil {
		return nil, fmt.Errorf("certificate already exists (id=%d, cn=%s)", existing.ID, existing.CommonName)
	}

	// 4. Build chain (AIA chasing)
	var intermediates []*x509.Certificate
	if len(result.Certificates) > 1 {
		intermediates = result.Certificates[1:]
	}
	chainResult := s.builder.BuildChain(leaf, intermediates)

	// 5. Build full chain PEM (leaf + intermediates from chain result)
	var pemBuilder strings.Builder
	for _, node := range chainResult.Chain {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: node.Certificate.Raw}
		pemBuilder.Write(pem.EncodeToMemory(block))
	}
	certPEM := pemBuilder.String()

	// 6. Handle private key
	var privateKeyEnc string
	var keyEncrypted bool

	// Parse separate private key if provided and not already in the bundle
	privKey := result.PrivateKey
	if privKey == nil && req.PrivateKey != "" {
		keyResult, err := s.parser.Parse([]byte(req.PrivateKey), req.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		privKey = keyResult.PrivateKey
		if privKey == nil {
			return nil, fmt.Errorf("no private key found in private_key input")
		}
	}

	if privKey != nil {
		// Check if the original key was encrypted (password-protected input)
		keyEncrypted = req.Password != ""

		// Marshal to PKCS#8 PEM, then Tink-encrypt
		keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

		encrypted, err := s.enc.Encrypt(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
		privateKeyEnc = encrypted
	}

	// 7. Determine status
	status := "active"
	now := time.Now()
	if leaf.NotAfter.Before(now) {
		status = "expired"
	}

	// 8. Determine name
	name := req.Name
	if name == "" {
		name = cn
	}

	tags := req.Tags
	if tags == "" {
		tags = "[]"
	}

	notBefore := leaf.NotBefore
	notAfter := leaf.NotAfter

	cert := &Certificate{
		Name:              name,
		CommonName:        cn,
		SANs:              string(sans),
		SerialNumber:      serial,
		IssuerCN:          issuerCN,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		KeyAlgorithm:      keyAlgo,
		FingerprintSHA256: fingerprint,
		Status:            status,
		Source:            "manual",
		CertPEM:           certPEM,
		PrivateKeyEnc:     privateKeyEnc,
		KeyEncrypted:      keyEncrypted,
		Tags:              tags,
		Notes:             req.Notes,
		CreatedBy:         username,
	}

	if err := s.repo.Create(db, cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	// 9. Build warnings
	var warnings []chain.Warning
	warnings = append(warnings, chainResult.Warnings...)
	if !chainResult.Complete {
		warnings = append(warnings, chain.Warning{Code: "CHAIN_INCOMPLETE", Message: "Certificate chain is incomplete"})
	}
	daysRemaining := int(leaf.NotAfter.Sub(now).Hours() / 24)
	if daysRemaining < 30 && status == "active" {
		warnings = append(warnings, chain.Warning{
			Code:    "EXPIRY_WARNING",
			Message: fmt.Sprintf("Certificate expires in %d days", daysRemaining),
		})
	}

	dto := cert.ToDTO()
	return &ImportResult{Certificate: dto, Warnings: warnings}, nil
}

// List returns a paginated list of certificates.
func (s *Service) List(db *gorm.DB, q *ListQuery) (*ListResponse, error) {
	certs, total, err := s.repo.FindAll(db, q)
	if err != nil {
		return nil, err
	}

	items := make([]CertificateDTO, 0, len(certs))
	for _, c := range certs {
		items = append(items, c.ToDTO())
	}

	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}

	return &ListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// Get retrieves a single certificate by ID.
func (s *Service) Get(db *gorm.DB, id uint) (*CertificateDTO, error) {
	cert, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, err
	}
	dto := cert.ToDTO()
	return &dto, nil
}

// Update modifies certificate metadata (name, tags, notes).
func (s *Service) Update(db *gorm.DB, id uint, req *UpdateRequest) (*CertificateDTO, error) {
	cert, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, err
	}

	if req.Name != nil {
		cert.Name = *req.Name
	}
	if req.Tags != nil {
		cert.Tags = *req.Tags
	}
	if req.Notes != nil {
		cert.Notes = *req.Notes
	}

	if err := s.repo.Update(db, cert); err != nil {
		return nil, err
	}

	dto := cert.ToDTO()
	return &dto, nil
}

// Delete soft-deletes a certificate by ID.
func (s *Service) Delete(db *gorm.DB, id uint) error {
	_, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("certificate not found")
		}
		return err
	}
	return s.repo.Delete(db, id)
}

// Download exports a certificate in the requested format.
func (s *Service) Download(db *gorm.DB, id uint, q *DownloadQuery) (*converter.ConvertResult, error) {
	cert, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("certificate not found")
		}
		return nil, err
	}

	format := q.Format
	if format == "" {
		format = "pem"
	}

	// For PEM, return the stored PEM directly (includes chain)
	if format == "pem" {
		includeKey := cert.PrivateKeyEnc != ""
		data := cert.CertPEM

		if includeKey {
			keyPEM, err := s.enc.Decrypt(cert.PrivateKeyEnc)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt private key: %w", err)
			}
			data += keyPEM
		}

		return &converter.ConvertResult{
			Data:          []byte(data),
			Format:        "pem",
			FilenameSugg:  cert.CommonName + ".pem",
			ChainIncluded: true,
		}, nil
	}

	// For other formats, use the converter
	includeChain := true
	if q.IncludeChain != nil {
		includeChain = *q.IncludeChain
	}

	var privKeyPEM string
	if cert.PrivateKeyEnc != "" {
		decrypted, err := s.enc.Decrypt(cert.PrivateKeyEnc)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		privKeyPEM = decrypted
	}

	// Validate requirements
	if (format == "pfx" || format == "jks") && privKeyPEM == "" {
		return nil, fmt.Errorf("%s format requires a private key, but this certificate has none stored", format)
	}
	if (format == "pfx" || format == "jks") && q.Password == "" {
		return nil, fmt.Errorf("%s format requires a password", format)
	}

	convReq := &converter.ConvertRequest{
		Certificate:  cert.CertPEM,
		PrivateKey:   privKeyPEM,
		InputType:    "pem",
		Password:     q.Password,
		TargetFormat: format,
		IncludeChain: includeChain,
		FriendlyName: cert.Name,
	}

	return s.converter.Convert(convReq)
}

// ── Helpers ─────────────────────────────────────────────────────────────────

func describeKeyAlgorithm(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		return fmt.Sprintf("EC P-%d", pub.Curve.Params().BitSize)
	default:
		return "unknown"
	}
}

func computeSHA256Fingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	parts := make([]string, len(hash))
	for i, b := range hash {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

func extractSANsList(cert *x509.Certificate) []string {
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	return sans
}
