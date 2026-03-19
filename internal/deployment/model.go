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
	Status        string         `gorm:"default:'active'" json:"status"`    // active / removed
	DeployedAt    *time.Time     `json:"deployed_at"`
	DeployedBy    string         `json:"deployed_by"`
	Notes         string         `gorm:"type:text" json:"notes"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
}
