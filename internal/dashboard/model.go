package dashboard

import "time"

// HealthSummary is the response for GET /dashboard/health.
type HealthSummary struct {
	Counts              HealthCounts       `json:"counts"`
	CertsExpiringSoon   []CertWarning      `json:"certs_expiring_soon"`
	CertsExpiredActive  []CertWarning      `json:"certs_expired_active"`
	DeploymentsFailed   []DeployWarning    `json:"deployments_failed"`
	DeploymentsPending  []DeployWarning    `json:"deployments_pending_long"`
	AgentsOffline       []AgentWarning     `json:"agents_offline"`
	TokensExpired       []TokenWarning     `json:"tokens_expired"`
	AcmeOrdersFailed    []AcmeOrderWarning `json:"acme_orders_failed"`
}

type HealthCounts struct {
	CertsExpiringSoon  int `json:"certs_expiring_soon"`
	CertsExpiredActive int `json:"certs_expired_active"`
	DeploymentsFailed  int `json:"deployments_failed"`
	DeploymentsPending int `json:"deployments_pending_long"`
	AgentsOffline      int `json:"agents_offline"`
	TokensExpired      int `json:"tokens_expired"`
	AcmeOrdersFailed   int `json:"acme_orders_failed"`
}

type CertWarning struct {
	ID            uint       `json:"id"`
	Name          string     `json:"name"`
	CommonName    string     `json:"common_name"`
	NotAfter      *time.Time `json:"not_after"`
	DaysRemaining int        `json:"days_remaining"`
	Source        string     `json:"source"`
}

type DeployWarning struct {
	ID            uint       `json:"id"`
	CertificateID uint      `json:"certificate_id"`
	TargetHost    string     `json:"target_host"`
	TargetService string     `json:"target_service"`
	DeployStatus  string     `json:"deploy_status"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type AgentWarning struct {
	ID         uint       `json:"id"`
	AgentID    string     `json:"agent_id"`
	Name       string     `json:"name"`
	Hostname   string     `json:"hostname"`
	Status     string     `json:"status"`
	LastSeenAt *time.Time `json:"last_seen_at"`
}

type TokenWarning struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	TokenPrefix string     `json:"token_prefix"`
	Label       string     `json:"label"`
	Status      string     `json:"status"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type AcmeOrderWarning struct {
	ID           uint   `json:"id"`
	Domains      string `json:"domains"`
	Status       string `json:"status"`
	ErrorMessage string `json:"error_message"`
}
