package deployment

import (
	"time"

	"gorm.io/gorm"
)

func (Deployment) TableName() string { return "hycert_deployments" }

type Deployment struct {
	ID            uint           `gorm:"primaryKey" json:"id"`
	CertificateID uint          `gorm:"not null;index" json:"certificate_id"`
	TargetHost    string         `gorm:"not null" json:"target_host"`        // IP or hostname
	TargetService string        `gorm:"not null" json:"target_service"`     // nginx / apache / tomcat / k8s
	TargetDetail  string         `gorm:"type:text" json:"target_detail"`    // path, namespace, etc.
	Port          *int           `json:"port"`
	Status          string         `gorm:"default:'active'" json:"status"`    // active / removed
	DeployedAt      *time.Time     `json:"deployed_at"`
	DeployedBy      string         `json:"deployed_by"`
	Notes           string         `gorm:"type:text" json:"notes"`
	LastFingerprint string         `json:"last_fingerprint,omitempty"`
	LastDeployedAt  *time.Time     `json:"last_deployed_at,omitempty"`
	AgentTokenID    *uint          `json:"agent_token_id,omitempty"`
	DeployStatus    string         `gorm:"default:'pending'" json:"deploy_status"` // pending / deploying / deployed / failed
	AgentID         *string        `gorm:"type:varchar(36)" json:"agent_id,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
}

// CreateDeploymentRequest is the payload for creating a deployment record.
type CreateDeploymentRequest struct {
	CertificateID uint   `json:"certificate_id" binding:"required"`
	TargetHost    string `json:"target_host" binding:"required"`
	TargetService string `json:"target_service" binding:"required"`
	TargetDetail  string `json:"target_detail,omitempty"`
	Port          *int    `json:"port,omitempty"`
	Notes         string  `json:"notes,omitempty"`
	AgentID       *string `json:"agent_id,omitempty"`
}

// UpdateDeploymentRequest is the payload for updating a deployment record.
type UpdateDeploymentRequest struct {
	TargetHost    *string `json:"target_host,omitempty"`
	TargetService *string `json:"target_service,omitempty"`
	TargetDetail  *string `json:"target_detail,omitempty"`
	Port          *int    `json:"port,omitempty"`
	Status        *string `json:"status,omitempty"`
	Notes         *string `json:"notes,omitempty"`
	AgentID       *string `json:"agent_id,omitempty"`
}

// DeploymentListQuery captures query parameters for listing deployments.
type DeploymentListQuery struct {
	Page          int    `form:"page,default=1"`
	PageSize      int    `form:"page_size,default=20"`
	CertificateID uint   `form:"certificate_id"`
	Search        string `form:"search"`        // target_host or target_service substring
	Status        string `form:"status"`        // active | removed
	DeployStatus  string `form:"deploy_status"` // pending | deployed | failed
}

// DeploymentListResponse wraps a paginated list of deployments.
type DeploymentListResponse struct {
	Items      []Deployment `json:"items"`
	Total      int64        `json:"total"`
	Page       int          `json:"page"`
	PageSize   int          `json:"page_size"`
	TotalPages int          `json:"total_pages"`
}
