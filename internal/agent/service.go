package agent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Service handles agent token management and deployment operations.
type Service struct {
	repo *Repository
	log  *zap.Logger
}

// NewService creates a new agent Service.
func NewService(repo *Repository, log *zap.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// ── Token Management ────────────────────────────────────────────────────────

// CreateToken generates a new agent token for a tenant.
func (s *Service) CreateToken(adminDB *gorm.DB, req *CreateTokenRequest, tenantCode, username string) (*CreateTokenResponse, error) {
	// Generate random token: hycert_agt_ + 32 random hex chars
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	rawToken := "hycert_agt_" + hex.EncodeToString(tokenBytes)
	prefix := rawToken[:19] // "hycert_agt_" + first 8 hex chars

	// SHA-256 hash for storage
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	// Marshal allowed_hosts
	allowedHosts := "[]"
	if len(req.AllowedHosts) > 0 {
		b, err := json.Marshal(req.AllowedHosts)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal allowed_hosts: %w", err)
		}
		allowedHosts = string(b)
	}

	// Parse expires_at
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at format (use RFC3339): %w", err)
		}
		expiresAt = &t
	}

	token := &AgentToken{
		Name:         req.Name,
		TokenHash:    tokenHash,
		TokenPrefix:  prefix,
		TenantCode:   tenantCode,
		AllowedHosts: allowedHosts,
		ExpiresAt:    expiresAt,
		Status:       "active",
		CreatedBy:    username,
	}

	if err := s.repo.CreateToken(adminDB, token); err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &CreateTokenResponse{
		Token:         rawToken,
		AgentTokenDTO: token.ToDTO(),
	}, nil
}

// ListTokens returns tokens for a tenant.
func (s *Service) ListTokens(adminDB *gorm.DB, tenantCode string, q *TokenListQuery) (*TokenListResponse, error) {
	tokens, total, err := s.repo.FindAllTokens(adminDB, tenantCode, q)
	if err != nil {
		return nil, err
	}

	items := make([]AgentTokenDTO, 0, len(tokens))
	for _, t := range tokens {
		items = append(items, t.ToDTO())
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

	return &TokenListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// GetToken retrieves a single token by ID for a tenant.
func (s *Service) GetToken(adminDB *gorm.DB, id uint, tenantCode string) (*AgentTokenDTO, error) {
	token, err := s.repo.FindTokenByID(adminDB, id, tenantCode)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}
	dto := token.ToDTO()
	return &dto, nil
}

// RevokeToken soft-deletes a token.
func (s *Service) RevokeToken(adminDB *gorm.DB, id uint, tenantCode string) error {
	token, err := s.repo.FindTokenByID(adminDB, id, tenantCode)
	if err != nil {
		return fmt.Errorf("token not found")
	}
	token.Status = "revoked"
	return s.repo.UpdateToken(adminDB, token)
}

// ── Agent Authentication ────────────────────────────────────────────────────

// Authenticate validates an agent token and returns the token record.
func (s *Service) Authenticate(adminDB *gorm.DB, rawToken string) (*AgentToken, error) {
	hash := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(hash[:])

	token, err := s.repo.FindTokenByHash(adminDB, tokenHash)
	if err != nil {
		return nil, fmt.Errorf("invalid token")
	}

	// Check expiry
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token expired")
	}

	// Update last_used_at (best-effort)
	go func() {
		if err := s.repo.UpdateLastUsed(adminDB, token.ID); err != nil {
			s.log.Warn("failed to update token last_used_at", zap.Error(err))
		}
	}()

	return token, nil
}

// ── Agent Deployment Operations ─────────────────────────────────────────────

// UpdateDeployStatus records a deployment status update from an agent.
func (s *Service) UpdateDeployStatus(tenantDB *gorm.DB, deploymentID uint, tokenID uint, req *UpdateDeployStatusRequest) error {
	// Verify deployment exists
	var deploy struct {
		ID            uint
		CertificateID uint
	}
	err := tenantDB.Table("hycert_deployments").
		Where("id = ? AND status = 'active' AND deleted_at IS NULL", deploymentID).
		First(&deploy).Error
	if err != nil {
		return fmt.Errorf("deployment not found")
	}

	// Record history
	now := time.Now()
	history := &DeploymentHistory{
		DeploymentID:  deploymentID,
		CertificateID: deploy.CertificateID,
		AgentTokenID:  &tokenID,
		Fingerprint:   req.Fingerprint,
		Action:        req.Action,
		Status:        req.Status,
		ErrorMessage:  req.ErrorMessage,
		DurationMs:    req.DurationMs,
		DeployedAt:    now,
	}
	if err := s.repo.CreateHistory(tenantDB, history); err != nil {
		return fmt.Errorf("failed to record history: %w", err)
	}

	// Update deployment status
	updates := map[string]interface{}{
		"updated_at": now,
	}
	if req.Status == "success" {
		updates["deploy_status"] = "deployed"
		updates["last_deployed_at"] = now
		if req.Fingerprint != "" {
			updates["last_fingerprint"] = req.Fingerprint
		}
	} else {
		updates["deploy_status"] = "failed"
	}

	return tenantDB.Table("hycert_deployments").Where("id = ?", deploymentID).Updates(updates).Error
}

// GetDeploymentHistory returns history for a deployment.
func (s *Service) GetDeploymentHistory(tenantDB *gorm.DB, deploymentID uint, q *HistoryListQuery) (*HistoryListResponse, error) {
	history, total, err := s.repo.FindHistoryByDeployment(tenantDB, deploymentID, q)
	if err != nil {
		return nil, err
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

	return &HistoryListResponse{
		Items:      history,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// ── Agent Registration ────────────────────────────────────────────────────────

// RegisterAgent creates or updates an agent registration (upsert).
func (s *Service) RegisterAgent(tenantDB *gorm.DB, tokenID uint, req *RegisterAgentRequest) (*AgentRegistrationDTO, error) {
	ipJSON := "[]"
	if len(req.IPAddresses) > 0 {
		b, _ := json.Marshal(req.IPAddresses)
		ipJSON = string(b)
	}

	now := time.Now()
	reg := &AgentRegistration{
		AgentID:      req.AgentID,
		AgentTokenID: tokenID,
		Name:         req.Name,
		Hostname:     req.Hostname,
		IPAddresses:  ipJSON,
		OS:           req.OS,
		Version:      req.Version,
		PollInterval: req.Interval,
		Status:       "active",
		LastSeenAt:   &now,
	}

	if err := s.repo.UpsertRegistration(tenantDB, reg); err != nil {
		return nil, fmt.Errorf("failed to register agent: %w", err)
	}

	// Re-read to get full record
	saved, err := s.repo.FindRegistrationByAgentID(tenantDB, req.AgentID)
	if err != nil {
		return nil, err
	}
	dto := saved.ToDTO()
	return &dto, nil
}

// GetDeploymentsByAgentID returns deployments linked to a specific agent UUID.
// Returns an error if the agent is disabled.
func (s *Service) GetDeploymentsByAgentID(tenantDB *gorm.DB, agentID string) ([]AgentDeploymentDTO, error) {
	// Check agent status
	reg, err := s.repo.FindRegistrationByAgentID(tenantDB, agentID)
	if err == nil && reg.Status == "disabled" {
		s.log.Warn("disabled agent attempted to fetch deployments",
			zap.String("agent_id", agentID),
			zap.String("hostname", reg.Hostname),
		)
		return nil, fmt.Errorf("agent is disabled")
	}
	type deployRow struct {
		ID              uint
		CertificateID   uint
		TargetHost      string
		TargetService   string
		TargetDetail    string
		Port            *int
		DeployStatus    string
		LastFingerprint string
		CertFingerprint string
		AgentID         string
	}

	var rows []deployRow
	err = tenantDB.Raw(`
		SELECT d.id, d.certificate_id, d.target_host, d.target_service,
		       d.target_detail, d.port, d.deploy_status, d.last_fingerprint,
		       d.agent_id,
		       c.fingerprint_sha256 AS cert_fingerprint
		FROM hycert_deployments d
		JOIN hycert_certificates c ON c.id = d.certificate_id AND c.deleted_at IS NULL
		WHERE d.agent_id = ? AND d.status = 'active' AND d.deleted_at IS NULL
	`, agentID).Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	result := make([]AgentDeploymentDTO, 0, len(rows))
	for _, r := range rows {
		result = append(result, AgentDeploymentDTO{
			ID:              r.ID,
			CertificateID:   r.CertificateID,
			TargetHost:      r.TargetHost,
			TargetService:   r.TargetService,
			TargetDetail:    r.TargetDetail,
			Port:            r.Port,
			DeployStatus:    r.DeployStatus,
			LastFingerprint: r.LastFingerprint,
			CertFingerprint: r.CertFingerprint,
			AgentID:         r.AgentID,
		})
	}
	return result, nil
}

// UpdateRegistrationStatus enables or disables an agent registration.
func (s *Service) UpdateRegistrationStatus(tenantDB *gorm.DB, id uint, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("invalid status: must be 'active' or 'disabled'")
	}
	var reg AgentRegistration
	if err := tenantDB.Where("id = ? AND deleted_at IS NULL", id).First(&reg).Error; err != nil {
		return fmt.Errorf("agent not found")
	}
	return tenantDB.Model(&reg).Update("status", status).Error
}

// ListRegistrations returns all registered agents for a tenant.
func (s *Service) ListRegistrations(tenantDB *gorm.DB, q *AgentRegistrationListQuery) (*AgentRegistrationListResponse, error) {
	regs, total, err := s.repo.FindAllRegistrations(tenantDB, q)
	if err != nil {
		return nil, err
	}

	items := make([]AgentRegistrationDTO, 0, len(regs))
	for _, r := range regs {
		items = append(items, r.ToDTO())
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

	return &AgentRegistrationListResponse{
		Items:      items,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}
