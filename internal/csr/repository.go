package csr

import (
	"gorm.io/gorm"
)

// Repository handles CSR persistence operations.
type Repository struct{}

// NewRepository creates a new Repository.
func NewRepository() *Repository {
	return &Repository{}
}

// Create inserts a new CSR record.
func (r *Repository) Create(db *gorm.DB, csr *CSR) error {
	return db.Create(csr).Error
}

// FindByID retrieves a CSR by ID.
func (r *Repository) FindByID(db *gorm.DB, id uint) (*CSR, error) {
	var c CSR
	if err := db.First(&c, id).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

// FindAll retrieves CSRs with pagination and optional status filter.
func (r *Repository) FindAll(db *gorm.DB, q *CSRListQuery) ([]CSR, int64, error) {
	tx := db.Model(&CSR{})

	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}
	if q.Search != "" {
		like := "%" + q.Search + "%"
		tx = tx.Where("common_name ILIKE ? OR sans ILIKE ?", like, like)
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

	var csrs []CSR
	if err := tx.Find(&csrs).Error; err != nil {
		return nil, 0, err
	}
	return csrs, total, nil
}

// UpdateStatus updates the status and optionally links to a certificate.
func (r *Repository) UpdateStatus(db *gorm.DB, id uint, status string, certID *uint) error {
	updates := map[string]interface{}{"status": status}
	if certID != nil {
		updates["certificate_id"] = *certID
	}
	return db.Model(&CSR{}).Where("id = ?", id).Updates(updates).Error
}

// Delete soft-deletes a CSR.
func (r *Repository) Delete(db *gorm.DB, id uint) error {
	return db.Delete(&CSR{}, id).Error
}
