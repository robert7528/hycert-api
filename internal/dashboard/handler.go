package dashboard

import (
	"math"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/robert7528/hycore/middleware"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// Handler handles health dashboard requests.
type Handler struct {
	adminDB *gorm.DB
	log     *zap.Logger
}

// NewHandler creates a new dashboard Handler.
func NewHandler(adminDB *gorm.DB, log *zap.Logger) *Handler {
	return &Handler{adminDB: adminDB, log: log}
}

// GetHealthSummary handles GET /dashboard/health
func (h *Handler) GetHealthSummary(c *gin.Context) {
	tenantDB := middleware.GetTenantDB(c)
	if tenantDB == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	now := time.Now()
	summary := HealthSummary{}

	// 1. Certificates expiring within 30 days
	var expiring []struct {
		ID         uint
		Name       string
		CommonName string
		NotAfter   *time.Time
		Source     string
	}
	tenantDB.Table("hycert_certificates").
		Select("id, name, common_name, not_after, source").
		Where("status = 'active' AND not_after <= NOW() + INTERVAL '30 days' AND not_after > NOW() AND deleted_at IS NULL").
		Order("not_after ASC").Find(&expiring)
	for _, c := range expiring {
		days := 0
		if c.NotAfter != nil {
			days = int(math.Ceil(time.Until(*c.NotAfter).Hours() / 24))
		}
		summary.CertsExpiringSoon = append(summary.CertsExpiringSoon, CertWarning{
			ID: c.ID, Name: c.Name, CommonName: c.CommonName,
			NotAfter: c.NotAfter, DaysRemaining: days, Source: c.Source,
		})
	}

	// 2. Expired certificates that still have active deployments
	var expiredDeployed []struct {
		ID         uint
		Name       string
		CommonName string
		NotAfter   *time.Time
		Source     string
	}
	tenantDB.Table("hycert_certificates").
		Select("hycert_certificates.id, hycert_certificates.name, hycert_certificates.common_name, hycert_certificates.not_after, hycert_certificates.source").
		Where("hycert_certificates.not_after < NOW() AND hycert_certificates.deleted_at IS NULL AND EXISTS (SELECT 1 FROM hycert_deployments d WHERE d.certificate_id = hycert_certificates.id AND d.status = 'active' AND d.deleted_at IS NULL)").
		Find(&expiredDeployed)
	for _, c := range expiredDeployed {
		days := 0
		if c.NotAfter != nil {
			d := int(math.Ceil(time.Since(*c.NotAfter).Hours() / 24))
			days = -d // negative = expired N days ago
		}
		summary.CertsExpiredActive = append(summary.CertsExpiredActive, CertWarning{
			ID: c.ID, Name: c.Name, CommonName: c.CommonName,
			NotAfter: c.NotAfter, DaysRemaining: days, Source: c.Source,
		})
	}

	// 3. Deployments failed
	var deployFailed []struct {
		ID            uint
		CertificateID uint `gorm:"column:certificate_id"`
		TargetHost    string
		TargetService string
		DeployStatus  string `gorm:"column:deploy_status"`
		UpdatedAt     time.Time
	}
	tenantDB.Table("hycert_deployments").
		Select("id, certificate_id, target_host, target_service, deploy_status, updated_at").
		Where("deploy_status = 'failed' AND status = 'active' AND deleted_at IS NULL").
		Find(&deployFailed)
	for _, d := range deployFailed {
		summary.DeploymentsFailed = append(summary.DeploymentsFailed, DeployWarning{
			ID: d.ID, CertificateID: d.CertificateID, TargetHost: d.TargetHost,
			TargetService: d.TargetService, DeployStatus: d.DeployStatus, UpdatedAt: d.UpdatedAt,
		})
	}

	// 4. Deployments pending > 24h
	var deployPending []struct {
		ID            uint
		CertificateID uint `gorm:"column:certificate_id"`
		TargetHost    string
		TargetService string
		DeployStatus  string `gorm:"column:deploy_status"`
		UpdatedAt     time.Time
	}
	tenantDB.Table("hycert_deployments").
		Select("id, certificate_id, target_host, target_service, deploy_status, updated_at").
		Where("deploy_status = 'pending' AND status = 'active' AND updated_at < ? AND deleted_at IS NULL", now.Add(-24*time.Hour)).
		Find(&deployPending)
	for _, d := range deployPending {
		summary.DeploymentsPending = append(summary.DeploymentsPending, DeployWarning{
			ID: d.ID, CertificateID: d.CertificateID, TargetHost: d.TargetHost,
			TargetService: d.TargetService, DeployStatus: d.DeployStatus, UpdatedAt: d.UpdatedAt,
		})
	}

	// 5. Agents offline or disabled
	var agents []struct {
		ID           uint
		AgentID      string `gorm:"column:agent_id"`
		Name         string
		Hostname     string
		Status       string
		PollInterval int    `gorm:"column:poll_interval"`
		LastSeenAt   *time.Time `gorm:"column:last_seen_at"`
	}
	tenantDB.Table("hycert_agent_registrations").
		Select("id, agent_id, name, hostname, status, poll_interval, last_seen_at").
		Where("deleted_at IS NULL AND (status = 'disabled' OR (status = 'active' AND last_seen_at < NOW() - INTERVAL '1 second' * poll_interval * 2))").
		Find(&agents)
	for _, a := range agents {
		summary.AgentsOffline = append(summary.AgentsOffline, AgentWarning{
			ID: a.ID, AgentID: a.AgentID, Name: a.Name,
			Hostname: a.Hostname, Status: a.Status, LastSeenAt: a.LastSeenAt,
		})
	}

	// 6. Tokens expired or revoked (admin DB)
	claims := middleware.GetClaims(c)
	tenantCode := ""
	if claims != nil {
		tenantCode = claims.TenantCode
	}
	var tokens []struct {
		ID          uint
		Name        string
		TokenPrefix string `gorm:"column:token_prefix"`
		Label       string
		Status      string
		ExpiresAt   *time.Time `gorm:"column:expires_at"`
	}
	h.adminDB.Table("hycert_agent_tokens").
		Select("id, name, token_prefix, label, status, expires_at").
		Where("tenant_code = ? AND deleted_at IS NULL AND (status = 'revoked' OR (expires_at IS NOT NULL AND expires_at < NOW()))", tenantCode).
		Find(&tokens)
	for _, t := range tokens {
		summary.TokensExpired = append(summary.TokensExpired, TokenWarning{
			ID: t.ID, Name: t.Name, TokenPrefix: t.TokenPrefix,
			Label: t.Label, Status: t.Status, ExpiresAt: t.ExpiresAt,
		})
	}

	// 7. ACME orders failed
	var orders []struct {
		ID           uint
		Domains      string
		Status       string
		ErrorMessage string `gorm:"column:error_message"`
	}
	tenantDB.Table("hycert_acme_orders").
		Select("id, domains, status, error_message").
		Where("status = 'failed' AND deleted_at IS NULL").
		Find(&orders)
	for _, o := range orders {
		summary.AcmeOrdersFailed = append(summary.AcmeOrdersFailed, AcmeOrderWarning{
			ID: o.ID, Domains: o.Domains, Status: o.Status, ErrorMessage: o.ErrorMessage,
		})
	}

	// Counts
	summary.Counts = HealthCounts{
		CertsExpiringSoon:  len(summary.CertsExpiringSoon),
		CertsExpiredActive: len(summary.CertsExpiredActive),
		DeploymentsFailed:  len(summary.DeploymentsFailed),
		DeploymentsPending: len(summary.DeploymentsPending),
		AgentsOffline:      len(summary.AgentsOffline),
		TokensExpired:      len(summary.TokensExpired),
		AcmeOrdersFailed:   len(summary.AcmeOrdersFailed),
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": summary})
}
