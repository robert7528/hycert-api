package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	legocert "github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/registration"
	certpkg "github.com/hysp/hycert-api/internal/certificate"
	"github.com/robert7528/hycore/crypto"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Service handles ACME account and order operations.
type Service struct {
	repo    *Repository
	lego    *LegoClient
	certSvc *certpkg.Service
	enc     crypto.Encryptor
	log     *zap.Logger
}

// NewService creates a new ACME Service.
func NewService(
	repo *Repository,
	lego *LegoClient,
	certSvc *certpkg.Service,
	enc crypto.Encryptor,
	log *zap.Logger,
) *Service {
	return &Service{
		repo:    repo,
		lego:    lego,
		certSvc: certSvc,
		enc:     enc,
		log:     log,
	}
}

// ── Account Management ──────────────────────────────────────────────────────

// CreateAccount registers a new ACME account.
func (s *Service) CreateAccount(db *gorm.DB, req *CreateAccountRequest, username string) (*AcmeAccountDTO, error) {
	// Generate account key pair
	privKey, keyPEM, err := s.lego.GenerateAccountKey()
	if err != nil {
		return nil, err
	}

	// Register with ACME server
	user := &LegoUser{
		Email: req.Email,
		Key:   privKey,
	}
	reg, err := s.lego.Register(user, req.DirectoryURL)
	if err != nil {
		return nil, err
	}

	// Tink-encrypt the private key
	encKey, err := s.enc.Encrypt(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt account key: %w", err)
	}

	// Serialize registration
	regJSON, _ := json.Marshal(reg)

	acct := &AcmeAccount{
		Name:          req.Name,
		Email:         req.Email,
		DirectoryURL:  req.DirectoryURL,
		PrivateKeyEnc: encKey,
		Registration:  string(regJSON),
		Status:        "active",
		CreatedBy:     username,
	}

	if err := s.repo.CreateAccount(db, acct); err != nil {
		return nil, fmt.Errorf("save account: %w", err)
	}

	dto := acct.ToDTO()
	return &dto, nil
}

// ListAccounts returns ACME accounts.
func (s *Service) ListAccounts(db *gorm.DB, q *AccountListQuery) (*AccountListResponse, error) {
	accounts, total, err := s.repo.FindAllAccounts(db, q)
	if err != nil {
		return nil, err
	}

	items := make([]AcmeAccountDTO, 0, len(accounts))
	for _, a := range accounts {
		items = append(items, a.ToDTO())
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

	return &AccountListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetAccount retrieves a single ACME account.
func (s *Service) GetAccount(db *gorm.DB, id uint) (*AcmeAccountDTO, error) {
	acct, err := s.repo.FindAccountByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}
	dto := acct.ToDTO()
	return &dto, nil
}

// UpdateAccount modifies account metadata.
func (s *Service) UpdateAccount(db *gorm.DB, id uint, req *UpdateAccountRequest) (*AcmeAccountDTO, error) {
	acct, err := s.repo.FindAccountByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}

	if req.Name != nil {
		acct.Name = *req.Name
	}
	if req.Email != nil {
		acct.Email = *req.Email
	}
	if req.Status != nil {
		acct.Status = *req.Status
	}

	if err := s.repo.UpdateAccount(db, acct); err != nil {
		return nil, err
	}
	dto := acct.ToDTO()
	return &dto, nil
}

// DeleteAccount soft-deletes an ACME account.
func (s *Service) DeleteAccount(db *gorm.DB, id uint) error {
	_, err := s.repo.FindAccountByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("account not found")
		}
		return err
	}
	return s.repo.DeleteAccount(db, id)
}

// ── Order Management ────────────────────────────────────────────────────────

// CreateOrder initiates a new ACME certificate request.
func (s *Service) CreateOrder(db *gorm.DB, req *CreateOrderRequest, username string) (*AcmeOrderDTO, error) {
	// Validate account exists
	acct, err := s.repo.FindAccountByID(db, req.AccountID)
	if err != nil {
		return nil, fmt.Errorf("account not found")
	}
	if acct.Status != "active" {
		return nil, fmt.Errorf("account is not active")
	}

	// Marshal domains
	domainsJSON, _ := json.Marshal(req.Domains)

	// Encrypt DNS config if provided
	var dnsConfigEnc string
	if len(req.DNSConfig) > 0 && string(req.DNSConfig) != "null" {
		enc, err := s.enc.Encrypt(string(req.DNSConfig))
		if err != nil {
			return nil, fmt.Errorf("encrypt DNS config: %w", err)
		}
		dnsConfigEnc = enc
	}

	keyType := req.KeyType
	if keyType == "" {
		keyType = "ec256"
	}

	autoRenew := true
	if req.AutoRenew != nil {
		autoRenew = *req.AutoRenew
	}
	renewDays := 30
	if req.RenewBeforeDays != nil && *req.RenewBeforeDays > 0 {
		renewDays = *req.RenewBeforeDays
	}

	order := &AcmeOrder{
		AccountID:       req.AccountID,
		Domains:         string(domainsJSON),
		ChallengeType:   req.ChallengeType,
		DNSProvider:     req.DNSProvider,
		DNSConfigEnc:    dnsConfigEnc,
		KeyType:         keyType,
		Status:          "pending",
		AutoRenew:       autoRenew,
		RenewBeforeDays: renewDays,
		RequestedBy:     username,
	}

	if err := s.repo.CreateOrder(db, order); err != nil {
		return nil, fmt.Errorf("save order: %w", err)
	}

	// Execute ACME flow in background goroutine.
	// Use a context-free DB session so it survives after HTTP response is sent.
	bgDB := db.Session(&gorm.Session{NewDB: true})
	go s.executeOrder(bgDB, order, acct)

	dto := order.ToDTO()
	return &dto, nil
}

// ListOrders returns ACME orders.
func (s *Service) ListOrders(db *gorm.DB, q *OrderListQuery) (*OrderListResponse, error) {
	orders, total, err := s.repo.FindAllOrders(db, q)
	if err != nil {
		return nil, err
	}

	items := make([]AcmeOrderDTO, 0, len(orders))
	for _, o := range orders {
		items = append(items, o.ToDTO())
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

	return &OrderListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetOrder retrieves a single ACME order.
func (s *Service) GetOrder(db *gorm.DB, id uint) (*AcmeOrderDTO, error) {
	order, err := s.repo.FindOrderByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("order not found")
		}
		return nil, err
	}
	dto := order.ToDTO()
	return &dto, nil
}

// RenewOrder triggers a manual renewal for an existing order.
func (s *Service) RenewOrder(db *gorm.DB, id uint) (*AcmeOrderDTO, error) {
	order, err := s.repo.FindOrderByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("order not found")
		}
		return nil, err
	}

	if order.Status != "valid" {
		return nil, fmt.Errorf("can only renew orders with status 'valid', current: %s", order.Status)
	}

	acct, err := s.repo.FindAccountByID(db, order.AccountID)
	if err != nil {
		return nil, fmt.Errorf("account not found")
	}

	// Mark as processing
	order.Status = "processing"
	s.repo.UpdateOrder(db, order)

	bgDB := db.Session(&gorm.Session{NewDB: true})
	go s.executeRenewal(bgDB, order, acct)

	dto := order.ToDTO()
	return &dto, nil
}

// CancelOrder cancels a pending or processing order.
func (s *Service) CancelOrder(db *gorm.DB, id uint) error {
	order, err := s.repo.FindOrderByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("order not found")
		}
		return err
	}
	return s.repo.DeleteOrder(db, order.ID)
}

// ── ACME Flow Execution ─────────────────────────────────────────────────────

func (s *Service) executeOrder(db *gorm.DB, order *AcmeOrder, acct *AcmeAccount) {
	s.log.Info("executing ACME order", zap.Uint("order_id", order.ID), zap.String("domains", order.Domains))

	// Update status to processing
	order.Status = "processing"
	s.repo.UpdateOrder(db, order)

	// Decrypt account key
	user, err := s.buildLegoUser(acct)
	if err != nil {
		s.failOrder(db, order, err)
		return
	}

	// Decrypt DNS config if present
	dnsConfig, err := s.decryptDNSConfig(order)
	if err != nil {
		s.failOrder(db, order, err)
		return
	}

	// Parse domains
	var domains []string
	if err := json.Unmarshal([]byte(order.Domains), &domains); err != nil {
		s.failOrder(db, order, fmt.Errorf("parse domains: %w", err))
		return
	}

	// Obtain certificate
	certResource, err := s.lego.ObtainCertificate(user, acct.DirectoryURL, domains, order.ChallengeType, order.DNSProvider, dnsConfig, order.KeyType)
	if err != nil {
		s.failOrder(db, order, err)
		return
	}

	// Import certificate into hycert_certificates via certificate.Service
	certID, err := s.importACMECert(db, certResource, order)
	if err != nil {
		s.failOrder(db, order, fmt.Errorf("import cert: %w", err))
		return
	}

	// Update order
	now := time.Now()
	order.CertificateID = &certID
	order.Status = "valid"
	order.LastRenewedAt = &now
	s.repo.UpdateOrder(db, order)

	s.log.Info("ACME order completed", zap.Uint("order_id", order.ID), zap.Uint("certificate_id", certID))
}

func (s *Service) executeRenewal(db *gorm.DB, order *AcmeOrder, acct *AcmeAccount) {
	s.log.Info("executing ACME renewal", zap.Uint("order_id", order.ID))

	user, err := s.buildLegoUser(acct)
	if err != nil {
		s.failOrder(db, order, err)
		return
	}

	dnsConfig, err := s.decryptDNSConfig(order)
	if err != nil {
		s.failOrder(db, order, err)
		return
	}

	// Get existing certificate PEM for renewal
	var certPEM []byte
	if order.CertificateID != nil {
		var cert struct{ CertPEM string }
		if err := db.Table("hycert_certificates").Where("id = ?", *order.CertificateID).First(&cert).Error; err == nil {
			certPEM = []byte(cert.CertPEM)
		}
	}

	var certResource *legocert.Resource
	if len(certPEM) > 0 {
		certResource, err = s.lego.RenewCertificate(user, acct.DirectoryURL, certPEM, order.ChallengeType, order.DNSProvider, dnsConfig, order.KeyType)
	} else {
		// Fallback to new obtain if no existing cert
		var domains []string
		json.Unmarshal([]byte(order.Domains), &domains)
		certResource, err = s.lego.ObtainCertificate(user, acct.DirectoryURL, domains, order.ChallengeType, order.DNSProvider, dnsConfig, order.KeyType)
	}
	if err != nil {
		s.failOrder(db, order, err)
		return
	}

	// Store old cert ID for deployment update
	oldCertID := order.CertificateID

	// Import new certificate
	certID, err := s.importACMECert(db, certResource, order)
	if err != nil {
		s.failOrder(db, order, fmt.Errorf("import renewed cert: %w", err))
		return
	}

	// Update order
	now := time.Now()
	order.RenewFromID = oldCertID
	order.CertificateID = &certID
	order.Status = "valid"
	order.LastRenewedAt = &now
	s.repo.UpdateOrder(db, order)

	// Update deployments pointing to old certificate → new certificate
	if oldCertID != nil {
		db.Table("hycert_deployments").
			Where("certificate_id = ? AND status = 'active' AND deleted_at IS NULL", *oldCertID).
			Updates(map[string]interface{}{
				"certificate_id": certID,
				"deploy_status":  "pending",
				"updated_at":     now,
			})
	}

	s.log.Info("ACME renewal completed", zap.Uint("order_id", order.ID), zap.Uint("new_certificate_id", certID))
}

func (s *Service) buildLegoUser(acct *AcmeAccount) (*LegoUser, error) {
	keyPEM, err := s.enc.Decrypt(acct.PrivateKeyEnc)
	if err != nil {
		return nil, fmt.Errorf("decrypt account key: %w", err)
	}

	privKey, err := s.lego.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse account key: %w", err)
	}

	var reg *registration.Resource
	if acct.Registration != "" {
		reg = &registration.Resource{}
		json.Unmarshal([]byte(acct.Registration), reg)
	}

	return &LegoUser{
		Email:        acct.Email,
		Registration: reg,
		Key:          privKey,
	}, nil
}

func (s *Service) decryptDNSConfig(order *AcmeOrder) (string, error) {
	if order.DNSConfigEnc == "" {
		return "", nil
	}
	return s.enc.Decrypt(order.DNSConfigEnc)
}

func (s *Service) importACMECert(db *gorm.DB, certResource *legocert.Resource, order *AcmeOrder) (uint, error) {
	// Build import request using the certificate PEM from ACME
	importReq := &certpkg.ImportRequest{
		Certificate: string(certResource.Certificate),
		PrivateKey:  string(certResource.PrivateKey),
		InputType:   "pem",
		Name:        fmt.Sprintf("ACME: %s", order.Domains),
	}

	result, err := s.certSvc.Import(db, importReq, "acme-auto")
	if err != nil {
		return 0, err
	}

	return result.Certificate.ID, nil
}

func (s *Service) failOrder(db *gorm.DB, order *AcmeOrder, err error) {
	s.log.Error("ACME order failed", zap.Uint("order_id", order.ID), zap.Error(err))
	order.Status = "failed"
	order.ErrorMessage = err.Error()
	s.repo.UpdateOrder(db, order)
}

// ── Renewal Scanner (called by scheduler) ───────────────────────────────────

// ScanAndRenew checks all tenants for orders that need renewal.
// Called by the scheduler job.
func (s *Service) ScanAndRenew(db *gorm.DB) error {
	orders, err := s.repo.FindRenewableOrders(db)
	if err != nil {
		return fmt.Errorf("find renewable orders: %w", err)
	}

	for _, order := range orders {
		acct, err := s.repo.FindAccountByID(db, order.AccountID)
		if err != nil {
			s.log.Error("skip renewal: account not found", zap.Uint("order_id", order.ID), zap.Error(err))
			continue
		}

		s.log.Info("triggering auto-renewal", zap.Uint("order_id", order.ID))
		order.Status = "processing"
		s.repo.UpdateOrder(db, &order)
		bgDB := db.Session(&gorm.Session{NewDB: true})
		go s.executeRenewal(bgDB, &order, acct)
	}

	return nil
}
