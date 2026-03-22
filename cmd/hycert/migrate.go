package main

import (
	"context"
	"fmt"

	"github.com/robert7528/hycore/config"
	"github.com/robert7528/hycore/database"
	"github.com/robert7528/hycore/migrator"
	"github.com/spf13/cobra"
)

const (
	adminMigrationsDir  = "migrations/admin"
	tenantMigrationsDir = "migrations/tenant"
)

func migrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Run database migrations",
	}
	cmd.AddCommand(migrateAdminCmd(), migrateTenantCmd(), migrateAllTenantsCmd())
	return cmd
}

func migrateAdminCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "admin",
		Short: "Apply hycert admin DB migrations (agent tokens, etc.)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Load()
			adminDB, err := database.Connect(cfg)
			if err != nil {
				return fmt.Errorf("connect admin DB: %w", err)
			}

			fmt.Println("Applying hycert admin migrations...")
			if err := migrator.Admin(context.Background(), adminDB, adminMigrationsDir); err != nil {
				return err
			}
			fmt.Println("Admin migrations applied successfully.")
			return nil
		},
	}
}

func migrateTenantCmd() *cobra.Command {
	var code string
	cmd := &cobra.Command{
		Use:   "tenant",
		Short: "Apply hycert migrations for a specific tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			if code == "" {
				return fmt.Errorf("--code is required")
			}
			return applyTenantMigration(code)
		},
	}
	cmd.Flags().StringVar(&code, "code", "", "Tenant code (required)")
	return cmd
}

func migrateAllTenantsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "all-tenants",
		Short: "Apply hycert migrations for all registered tenants",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Load()
			adminDB, err := database.Connect(cfg)
			if err != nil {
				return fmt.Errorf("connect admin DB: %w", err)
			}

			var configs []database.TenantDBConfig
			if err := adminDB.Find(&configs).Error; err != nil {
				return fmt.Errorf("list tenant DB configs: %w", err)
			}

			mgr := database.NewManager(adminDB)
			ctx := context.Background()
			var failed []string

			for _, cfg := range configs {
				fmt.Printf("  → tenant %s ...", cfg.TenantCode)
				tenantDB, err := mgr.GetDB(cfg.TenantCode)
				if err != nil {
					fmt.Printf(" ERROR: %v\n", err)
					failed = append(failed, cfg.TenantCode)
					continue
				}
				if err := migrator.Tenant(ctx, tenantDB, tenantMigrationsDir, cfg.Schema); err != nil {
					fmt.Printf(" ERROR: %v\n", err)
					failed = append(failed, cfg.TenantCode)
					continue
				}
				fmt.Println(" ok")
			}

			if len(failed) > 0 {
				return fmt.Errorf("migrations failed for tenants: %v", failed)
			}
			fmt.Printf("All %d tenant migrations applied successfully.\n", len(configs))
			return nil
		},
	}
}

func applyTenantMigration(tenantCode string) error {
	cfg := config.Load()
	adminDB, err := database.Connect(cfg)
	if err != nil {
		return fmt.Errorf("connect admin DB: %w", err)
	}

	var tenantCfg database.TenantDBConfig
	if err := adminDB.Where("tenant_code = ?", tenantCode).First(&tenantCfg).Error; err != nil {
		return fmt.Errorf("tenant %q not found: %w", tenantCode, err)
	}

	mgr := database.NewManager(adminDB)
	tenantDB, err := mgr.GetDB(tenantCode)
	if err != nil {
		return fmt.Errorf("connect tenant DB: %w", err)
	}

	fmt.Printf("Applying hycert migrations for tenant %q ...\n", tenantCode)
	if err := migrator.Tenant(context.Background(), tenantDB, tenantMigrationsDir, tenantCfg.Schema); err != nil {
		return err
	}
	fmt.Printf("Tenant %q hycert migrations applied successfully.\n", tenantCode)
	return nil
}
