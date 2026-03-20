package app

import (
	"github.com/hysp/hycert-api/internal/certificate"
	"github.com/hysp/hycert-api/internal/chain"
	"github.com/hysp/hycert-api/internal/converter"
	"github.com/hysp/hycert-api/internal/csr"
	"github.com/hysp/hycert-api/internal/deployment"
	"github.com/hysp/hycert-api/internal/health"
	"github.com/hysp/hycert-api/internal/parser"
	"github.com/hysp/hycert-api/internal/server"
	"github.com/hysp/hycert-api/internal/utility"
	coreauth "github.com/robert7528/hycore/auth"
	"github.com/robert7528/hycore/config"
	corecrypto "github.com/robert7528/hycore/crypto"
	"github.com/robert7528/hycore/database"
	"github.com/robert7528/hycore/logger"
	"go.uber.org/fx"
)

func Run() error {
	app := fx.New(
		fx.Provide(
			// Infrastructure
			config.Load,
			logger.New,
			server.New,

			// Database (admin DB + tenant DB manager)
			database.Connect,
			database.NewManager,

			// Crypto (Tink encryptor)
			func(cfg *config.Config) (corecrypto.Encryptor, error) {
				return corecrypto.New(cfg.Tink.Keyset)
			},

			// Auth (validation only, no providers — tokens issued by hyadmin-api)
			func(cfg *config.Config) *coreauth.Service {
				return coreauth.NewService(cfg)
			},

			// Parser
			parser.New,

			// Chain builder
			chain.NewRootStore,
			chain.NewFetcher,
			chain.NewBuilder,

			// Converter
			converter.New,

			// Utility (orchestration — existing tool APIs)
			utility.NewService,
			utility.NewHandler,

			// Certificate CRUD
			certificate.NewRepository,
			certificate.NewService,
			certificate.NewHandler,

			// CSR CRUD
			csr.NewRepository,
			csr.NewService,
			csr.NewHandler,

			// Deployment CRUD
			deployment.NewRepository,
			deployment.NewService,
			deployment.NewHandler,

			// Health
			health.NewHandler,
		),
		fx.Invoke(server.RegisterRoutes),
		fx.Invoke(server.Start),
	)
	app.Run()
	return nil
}
