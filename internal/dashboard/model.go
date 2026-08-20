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

// Retry states for AcmeOrderWarning.RetryState, describing whether the renewal
// scanner will ever pick this failed order up again on its own:
//
//   - RetryScheduled: the scanner will retry it once its backoff elapses.
//   - RetryExhausted: retry_count hit the limit; automatic retries have stopped.
//   - RetryManual:    the scanner can never reach it — either auto_renew is off, or
//     the order has no certificate yet (a failed *initial* issuance, which the
//     scanner's INNER JOIN on certificate_id excludes by design). Rows like this
//     stay on the dashboard forever unless someone acts on or deletes them, so they
//     need to be visually separable from problems that are still being worked on.
const (
	RetryScheduled = "scheduled"
	RetryExhausted = "exhausted"
	RetryManual    = "manual"
)

type AcmeOrderWarning struct {
	ID            uint       `json:"id"`
	Domains       string     `json:"domains"`
	Status        string     `json:"status"`
	ErrorMessage  string     `json:"error_message"`
	CertificateID *uint      `json:"certificate_id"`
	RetryCount    int        `json:"retry_count"`
	RetryState    string     `json:"retry_state"`
	LastAttemptAt *time.Time `json:"last_attempt_at"`
	LastRenewedAt *time.Time `json:"last_renewed_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}
