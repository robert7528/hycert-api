package app

import (
	"github.com/hysp/hycert-api/internal/chain"
	"github.com/hysp/hycert-api/internal/converter"
	"github.com/hysp/hycert-api/internal/health"
	"github.com/hysp/hycert-api/internal/parser"
	"github.com/hysp/hycert-api/internal/server"
	"github.com/hysp/hycert-api/internal/utility"
	coreauth "github.com/robert7528/hycore/auth"
	"github.com/robert7528/hycore/config"
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

			// Utility (orchestration)
			utility.NewService,
			utility.NewHandler,

			// Health
			health.NewHandler,
		),
		fx.Invoke(server.RegisterRoutes),
		fx.Invoke(server.Start),
	)
	app.Run()
	return nil
}
