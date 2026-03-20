package csr

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hysp/hycert-api/internal/utility"
	"github.com/robert7528/hycore/crypto"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Service handles CSR business logic.
type Service struct {
	repo    *Repository
	utilSvc *utility.Service
	enc     crypto.Encryptor
	log     *zap.Logger
}

// NewService creates a new CSR Service.
func NewService(repo *Repository, utilSvc *utility.Service, enc crypto.Encryptor, log *zap.Logger) *Service {
	return &Service{repo: repo, utilSvc: utilSvc, enc: enc, log: log}
}

// Generate creates a new CSR and stores it with the Tink-encrypted private key.
func (s *Service) Generate(db *gorm.DB, req *CreateCSRRequest, username string) (*CSRDTO, error) {
	// 1. Generate CSR + key pair via utility service
	genReq := &utility.GenerateCSRRequest{
		Domain:  req.Domain,
		SANs:    req.SANs,
		KeyType: req.KeyType,
		KeyBits: req.KeyBits,
	}
	genReq.Subject.O = req.Subject.O
	genReq.Subject.OU = req.Subject.OU
	genReq.Subject.C = req.Subject.C
	genReq.Subject.ST = req.Subject.ST
	genReq.Subject.L = req.Subject.L

	genResp, err := s.utilSvc.GenerateCSR(genReq)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CSR: %w", err)
	}

	// 2. Tink-encrypt the private key
	encKey, err := s.enc.Encrypt(genResp.PrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// 3. Build SANs JSON
	allSANs := []string{req.Domain}
	allSANs = append(allSANs, req.SANs...)
	sansJSON, _ := json.Marshal(allSANs)

	// 4. Build subject JSON
	subjectJSON, _ := json.Marshal(req.Subject)

	csrEntity := &CSR{
		CommonName:    req.Domain,
		SANs:          string(sansJSON),
		Subject:       string(subjectJSON),
		KeyAlgorithm:  genResp.KeyType,
		KeyBits:       genResp.KeyBits,
		CSRPEM:        genResp.CSRPEM,
		PrivateKeyEnc: encKey,
		Status:        "pending",
		CreatedBy:     username,
	}

	if err := s.repo.Create(db, csrEntity); err != nil {
		return nil, fmt.Errorf("failed to save CSR: %w", err)
	}

	dto := csrEntity.ToDTO()
	return &dto, nil
}

// List returns a paginated list of CSRs.
func (s *Service) List(db *gorm.DB, q *CSRListQuery) (*CSRListResponse, error) {
	csrs, total, err := s.repo.FindAll(db, q)
	if err != nil {
		return nil, err
	}

	items := make([]CSRDTO, 0, len(csrs))
	for _, c := range csrs {
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

	return &CSRListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// Get retrieves a single CSR by ID.
func (s *Service) Get(db *gorm.DB, id uint) (*CSRDTO, error) {
	c, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("CSR not found")
		}
		return nil, err
	}
	dto := c.ToDTO()
	return &dto, nil
}

// Delete soft-deletes a CSR by ID.
func (s *Service) Delete(db *gorm.DB, id uint) error {
	_, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("CSR not found")
		}
		return err
	}
	return s.repo.Delete(db, id)
}

// Download returns the CSR PEM content.
func (s *Service) Download(db *gorm.DB, id uint) ([]byte, string, error) {
	c, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, "", fmt.Errorf("CSR not found")
		}
		return nil, "", err
	}

	// Parse CSR to extract CN for filename
	block, _ := pem.Decode([]byte(c.CSRPEM))
	filename := c.CommonName + ".csr"
	if block != nil {
		if csrParsed, err := x509.ParseCertificateRequest(block.Bytes); err == nil {
			filename = csrParsed.Subject.CommonName + ".csr"
		}
	}

	return []byte(c.CSRPEM), filename, nil
}
