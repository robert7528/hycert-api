package deployment

import (
	"gorm.io/gorm"
)

// Repository handles deployment persistence operations.
type Repository struct{}

// NewRepository creates a new Repository.
func NewRepository() *Repository {
	return &Repository{}
}

// Create inserts a new deployment record.
func (r *Repository) Create(db *gorm.DB, d *Deployment) error {
	return db.Create(d).Error
}

// FindByID retrieves a deployment by ID.
func (r *Repository) FindByID(db *gorm.DB, id uint) (*Deployment, error) {
	var d Deployment
	if err := db.First(&d, id).Error; err != nil {
		return nil, err
	}
	return &d, nil
}

// FindAll retrieves deployments with pagination and optional certificate_id filter.
func (r *Repository) FindAll(db *gorm.DB, q *DeploymentListQuery) ([]Deployment, int64, error) {
	tx := db.Model(&Deployment{})

	if q.CertificateID > 0 {
		tx = tx.Where("certificate_id = ?", q.CertificateID)
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

	var deployments []Deployment
	if err := tx.Find(&deployments).Error; err != nil {
		return nil, 0, err
	}
	return deployments, total, nil
}

// Update saves changes to an existing deployment.
func (r *Repository) Update(db *gorm.DB, d *Deployment) error {
	return db.Save(d).Error
}

// Delete soft-deletes a deployment.
func (r *Repository) Delete(db *gorm.DB, id uint) error {
	return db.Delete(&Deployment{}, id).Error
}
