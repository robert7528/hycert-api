package scheduler

import (
	"math"
	"time"

	"github.com/hysp/hycert-api/internal/acme"
	"github.com/hysp/hycert-api/internal/certificate"
	"github.com/robert7528/hycore/database"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RegisterJobs sets up all scheduler jobs. Called during fx.Invoke.
func RegisterJobs(s *Scheduler, acmeSvc *acme.Service, certRepo *certificate.Repository, adminDB *gorm.DB, dbMgr *database.DBManager, log *zap.Logger) {
	if !s.cfg.Enabled {
		return
	}

	// Expiry sync job: update active → expired
	syncCron := s.cfg.ExpirySyncCron
	if syncCron == "" {
		syncCron = "30 2 * * *" // daily at 2:30 AM (before renewal at 3:00)
	}
	if err := s.AddFunc(syncCron, func() {
		expirySyncJob(certRepo, adminDB, dbMgr, log)
	}); err != nil {
		log.Error("failed to register expiry sync job", zap.Error(err))
	}
	log.Info("registered expiry sync job", zap.String("cron", syncCron))

	// ACME renewal job
	renewalCron := s.cfg.RenewalCron
	if renewalCron == "" {
		renewalCron = "0 3 * * *" // daily at 3:00 AM
	}
	if err := s.AddFunc(renewalCron, func() {
		renewalJob(acmeSvc, adminDB, dbMgr, log)
	}); err != nil {
		log.Error("failed to register renewal job", zap.Error(err))
	}
	log.Info("registered ACME renewal job", zap.String("cron", renewalCron))
}

// expirySyncJob updates expired certificates and logs expiry warnings.
func expirySyncJob(certRepo *certificate.Repository, adminDB *gorm.DB, dbMgr *database.DBManager, log *zap.Logger) {
	log.Info("running certificate expiry sync")

	configs := getTenantCodes(adminDB, log)
	if configs == nil {
		return
	}

	for _, cfg := range configs {
		tenantDB, err := dbMgr.GetDB(cfg.TenantCode)
		if err != nil {
			log.Error("failed to get tenant DB for expiry sync",
				zap.String("tenant", cfg.TenantCode), zap.Error(err))
			continue
		}

		// Step 1: Update active → expired
		count, err := certRepo.ExpireActiveCertificates(tenantDB)
		if err != nil {
			log.Error("expiry sync failed",
				zap.String("tenant", cfg.TenantCode), zap.Error(err))
			continue
		}
		if count > 0 {
			log.Info("certificates marked as expired",
				zap.String("tenant", cfg.TenantCode), zap.Int64("count", count))
		}

		// Step 2: Log warnings for certificates expiring within 30 days
		expiryReminderLog(certRepo, tenantDB, cfg.TenantCode, log)
	}

	log.Info("certificate expiry sync complete")
}

// expiryReminderLog logs warnings for certificates expiring soon.
func expiryReminderLog(certRepo *certificate.Repository, db *gorm.DB, tenantCode string, log *zap.Logger) {
	certs, err := certRepo.FindExpiringSoon(db, 30)
	if err != nil {
		log.Error("failed to query expiring certificates",
			zap.String("tenant", tenantCode), zap.Error(err))
		return
	}

	now := time.Now()
	for _, cert := range certs {
		daysRemaining := 0
		if cert.NotAfter != nil {
			daysRemaining = int(math.Ceil(time.Until(*cert.NotAfter).Hours() / 24))
		}
		log.Warn("certificate expiring soon",
			zap.String("tenant", tenantCode),
			zap.Uint("cert_id", cert.ID),
			zap.String("cn", cert.CommonName),
			zap.Int("days_remaining", daysRemaining),
			zap.Timep("not_after", cert.NotAfter),
			zap.Time("now", now),
		)
	}
}

// renewalJob scans all tenants for orders due for renewal.
func renewalJob(acmeSvc *acme.Service, adminDB *gorm.DB, dbMgr *database.DBManager, log *zap.Logger) {
	log.Info("running ACME renewal scan")

	configs := getTenantCodes(adminDB, log)
	if configs == nil {
		return
	}

	for _, cfg := range configs {
		tenantDB, err := dbMgr.GetDB(cfg.TenantCode)
		if err != nil {
			log.Error("failed to get tenant DB for renewal",
				zap.String("tenant", cfg.TenantCode), zap.Error(err))
			continue
		}

		if err := acmeSvc.ScanAndRenew(tenantDB); err != nil {
			log.Error("renewal scan failed for tenant",
				zap.String("tenant", cfg.TenantCode), zap.Error(err))
		}
	}

	log.Info("ACME renewal scan complete")
}

// getTenantCodes retrieves all tenant codes from admin DB.
func getTenantCodes(adminDB *gorm.DB, log *zap.Logger) []struct{ TenantCode string } {
	var configs []struct {
		TenantCode string
	}
	if err := adminDB.Table("hyadmin_tenant_db_configs").Select("tenant_code").Find(&configs).Error; err != nil {
		log.Error("failed to list tenants", zap.Error(err))
		return nil
	}
	return configs
}
