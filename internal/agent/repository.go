package agent

import (
	"gorm.io/gorm"
)

// Repository handles agent token and deployment history persistence.
type Repository struct{}

// NewRepository creates a new agent Repository.
func NewRepository() *Repository {
	return &Repository{}
}

// ── Agent Token (admin DB) ──────────────────────────────────────────────────

// CreateToken inserts a new agent token record.
func (r *Repository) CreateToken(db *gorm.DB, token *AgentToken) error {
	return db.Create(token).Error
}

// FindTokenByHash retrieves an active token by its SHA-256 hash.
func (r *Repository) FindTokenByHash(db *gorm.DB, hash string) (*AgentToken, error) {
	var token AgentToken
	err := db.Where("token_hash = ? AND status = ?", hash, "active").First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// FindTokenByID retrieves a token by ID scoped to a tenant.
func (r *Repository) FindTokenByID(db *gorm.DB, id uint, tenantCode string) (*AgentToken, error) {
	var token AgentToken
	err := db.Where("id = ? AND tenant_code = ?", id, tenantCode).First(&token).Error
	if err != nil {
		return nil, err
	}
	return &token, nil
}

// FindAllTokens retrieves tokens with pagination for a specific tenant.
func (r *Repository) FindAllTokens(db *gorm.DB, tenantCode string, q *TokenListQuery) ([]AgentToken, int64, error) {
	tx := db.Model(&AgentToken{}).Where("tenant_code = ?", tenantCode)

	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	tx = tx.Order("created_at DESC").Offset((page - 1) * pageSize).Limit(pageSize)

	var tokens []AgentToken
	if err := tx.Find(&tokens).Error; err != nil {
		return nil, 0, err
	}
	return tokens, total, nil
}

// UpdateToken saves changes to an existing token.
func (r *Repository) UpdateToken(db *gorm.DB, token *AgentToken) error {
	return db.Save(token).Error
}

// DeleteToken soft-deletes a token.
func (r *Repository) DeleteToken(db *gorm.DB, id uint) error {
	return db.Delete(&AgentToken{}, id).Error
}

// UpdateLastUsed updates the last_used_at timestamp.
func (r *Repository) UpdateLastUsed(db *gorm.DB, id uint) error {
	return db.Model(&AgentToken{}).Where("id = ?", id).Update("last_used_at", gorm.Expr("NOW()")).Error
}

// ── Deployment History (tenant DB) ──────────────────────────────────────────

// CreateHistory inserts a deployment history record.
func (r *Repository) CreateHistory(db *gorm.DB, h *DeploymentHistory) error {
	return db.Create(h).Error
}

// FindHistoryByDeployment retrieves history for a deployment with pagination.
func (r *Repository) FindHistoryByDeployment(db *gorm.DB, deploymentID uint, q *HistoryListQuery) ([]DeploymentHistory, int64, error) {
	tx := db.Model(&DeploymentHistory{}).Where("deployment_id = ?", deploymentID)

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	tx = tx.Order("deployed_at DESC").Offset((page - 1) * pageSize).Limit(pageSize)

	var history []DeploymentHistory
	if err := tx.Find(&history).Error; err != nil {
		return nil, 0, err
	}
	return history, total, nil
}
