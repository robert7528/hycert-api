package deployment

import (
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Service handles deployment business logic.
type Service struct {
	repo *Repository
	log  *zap.Logger
}

// NewService creates a new deployment Service.
func NewService(repo *Repository, log *zap.Logger) *Service {
	return &Service{repo: repo, log: log}
}

// Create inserts a new deployment record.
func (s *Service) Create(db *gorm.DB, req *CreateDeploymentRequest, username string) (*Deployment, error) {
	now := time.Now()
	d := &Deployment{
		CertificateID: req.CertificateID,
		TargetHost:    req.TargetHost,
		TargetService: req.TargetService,
		TargetDetail:  req.TargetDetail,
		Port:          req.Port,
		Status:        "active",
		DeployedAt:    &now,
		DeployedBy:    username,
		Notes:         req.Notes,
	}

	if err := s.repo.Create(db, d); err != nil {
		return nil, fmt.Errorf("failed to create deployment: %w", err)
	}
	return d, nil
}

// List returns a paginated list of deployments.
func (s *Service) List(db *gorm.DB, q *DeploymentListQuery) (*DeploymentListResponse, error) {
	deployments, total, err := s.repo.FindAll(db, q)
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

	return &DeploymentListResponse{
		Items:      deployments,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
	}, nil
}

// Get retrieves a single deployment by ID.
func (s *Service) Get(db *gorm.DB, id uint) (*Deployment, error) {
	d, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("deployment not found")
		}
		return nil, err
	}
	return d, nil
}

// Update modifies a deployment record.
func (s *Service) Update(db *gorm.DB, id uint, req *UpdateDeploymentRequest) (*Deployment, error) {
	d, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("deployment not found")
		}
		return nil, err
	}

	if req.TargetHost != nil {
		d.TargetHost = *req.TargetHost
	}
	if req.TargetService != nil {
		d.TargetService = *req.TargetService
	}
	if req.TargetDetail != nil {
		d.TargetDetail = *req.TargetDetail
	}
	if req.Port != nil {
		d.Port = req.Port
	}
	if req.Status != nil {
		d.Status = *req.Status
	}
	if req.Notes != nil {
		d.Notes = *req.Notes
	}

	if err := s.repo.Update(db, d); err != nil {
		return nil, err
	}
	return d, nil
}

// Delete soft-deletes a deployment by ID.
func (s *Service) Delete(db *gorm.DB, id uint) error {
	_, err := s.repo.FindByID(db, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("deployment not found")
		}
		return err
	}
	return s.repo.Delete(db, id)
}
