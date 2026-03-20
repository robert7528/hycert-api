package certificate

import (
	"fmt"

	"gorm.io/gorm"
)

// Repository handles certificate persistence operations.
type Repository struct{}

// NewRepository creates a new Repository.
func NewRepository() *Repository {
	return &Repository{}
}

// Create inserts a new certificate record.
func (r *Repository) Create(db *gorm.DB, cert *Certificate) error {
	return db.Create(cert).Error
}

// FindByID retrieves a certificate by ID.
func (r *Repository) FindByID(db *gorm.DB, id uint) (*Certificate, error) {
	var cert Certificate
	if err := db.First(&cert, id).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

// FindByFingerprint retrieves a certificate by SHA-256 fingerprint.
func (r *Repository) FindByFingerprint(db *gorm.DB, fingerprint string) (*Certificate, error) {
	var cert Certificate
	if err := db.Where("fingerprint_sha256 = ?", fingerprint).First(&cert).Error; err != nil {
		return nil, err
	}
	return &cert, nil
}

// FindAll retrieves certificates with pagination and filtering.
func (r *Repository) FindAll(db *gorm.DB, q *ListQuery) ([]Certificate, int64, error) {
	tx := db.Model(&Certificate{})

	if q.Status != "" {
		tx = tx.Where("status = ?", q.Status)
	}
	if q.Search != "" {
		like := "%" + q.Search + "%"
		tx = tx.Where("name ILIKE ? OR common_name ILIKE ? OR sans::text ILIKE ?", like, like, like)
	}
	if q.ExpireIn > 0 {
		tx = tx.Where("not_after <= NOW() + INTERVAL '1 day' * ? AND not_after > NOW()", q.ExpireIn)
	}

	var total int64
	if err := tx.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Sort
	sortBy := q.SortBy
	if sortBy == "" {
		sortBy = "created_at"
	}
	sortDir := q.SortDir
	if sortDir == "" {
		sortDir = "desc"
	}
	allowedSort := map[string]bool{
		"created_at": true, "not_after": true, "common_name": true, "status": true,
	}
	if !allowedSort[sortBy] {
		sortBy = "created_at"
	}
	if sortDir != "asc" && sortDir != "desc" {
		sortDir = "desc"
	}
	tx = tx.Order(fmt.Sprintf("%s %s", sortBy, sortDir))

	// Pagination
	page := q.Page
	if page < 1 {
		page = 1
	}
	pageSize := q.PageSize
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	tx = tx.Offset((page - 1) * pageSize).Limit(pageSize)

	var certs []Certificate
	if err := tx.Find(&certs).Error; err != nil {
		return nil, 0, err
	}
	return certs, total, nil
}

// Update saves changes to an existing certificate.
func (r *Repository) Update(db *gorm.DB, cert *Certificate) error {
	return db.Save(cert).Error
}

// Delete soft-deletes a certificate.
func (r *Repository) Delete(db *gorm.DB, id uint) error {
	return db.Delete(&Certificate{}, id).Error
}
