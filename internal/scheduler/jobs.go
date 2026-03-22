package scheduler

import (
	"github.com/hysp/hycert-api/internal/acme"
	"github.com/robert7528/hycore/database"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// RegisterJobs sets up all scheduler jobs. Called during fx.Invoke.
func RegisterJobs(s *Scheduler, acmeSvc *acme.Service, adminDB *gorm.DB, dbMgr *database.DBManager, log *zap.Logger) {
	if !s.cfg.Enabled {
		return
	}

	cronSpec := s.cfg.RenewalCron
	if cronSpec == "" {
		cronSpec = "0 3 * * *" // default: daily at 3:00 AM
	}

	if err := s.AddFunc(cronSpec, func() {
		renewalJob(acmeSvc, adminDB, dbMgr, log)
	}); err != nil {
		log.Error("failed to register renewal job", zap.Error(err))
	}

	log.Info("registered ACME renewal job", zap.String("cron", cronSpec))
}

// renewalJob scans all tenants for orders due for renewal.
func renewalJob(acmeSvc *acme.Service, adminDB *gorm.DB, dbMgr *database.DBManager, log *zap.Logger) {
	log.Info("running ACME renewal scan")

	// Get all tenant codes
	var configs []struct {
		TenantCode string
	}
	if err := adminDB.Table("hyadmin_tenant_db_configs").Select("tenant_code").Find(&configs).Error; err != nil {
		log.Error("failed to list tenants for renewal scan", zap.Error(err))
		return
	}

	for _, cfg := range configs {
		tenantDB, err := dbMgr.GetDB(cfg.TenantCode)
		if err != nil {
			log.Error("failed to get tenant DB for renewal",
				zap.String("tenant", cfg.TenantCode),
				zap.Error(err),
			)
			continue
		}

		if err := acmeSvc.ScanAndRenew(tenantDB); err != nil {
			log.Error("renewal scan failed for tenant",
				zap.String("tenant", cfg.TenantCode),
				zap.Error(err),
			)
		}
	}

	log.Info("ACME renewal scan complete")
}
