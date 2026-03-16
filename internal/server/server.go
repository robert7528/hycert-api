package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hysp/hycert-api/internal/health"
	"github.com/hysp/hycert-api/internal/utility"
	coreauth "github.com/robert7528/hycore/auth"
	"github.com/robert7528/hycore/config"
	"github.com/robert7528/hycore/middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Server struct {
	engine *gin.Engine
	cfg    *config.Config
	log    *zap.Logger
}

func New(cfg *config.Config, log *zap.Logger) *Server {
	gin.SetMode(cfg.Server.Mode)
	engine := gin.New()
	return &Server{engine: engine, cfg: cfg, log: log}
}

// RouteParams groups all handler dependencies for fx injection.
type RouteParams struct {
	fx.In
	Server  *Server
	Health  *health.Handler
	AuthSvc *coreauth.Service
	Utility *utility.Handler
}

func RegisterRoutes(p RouteParams) {
	r := p.Server.engine
	r.Use(middleware.Recovery(p.Server.log))

	api := r.Group("/api/v1")

	// ── Public routes (no JWT) ──────────────────────────────────────────
	api.GET("/health", p.Health.Check)

	// ── Admin routes (JWT-protected) ────────────────────────────────────
	adm := api.Group("/adm/cert")
	adm.Use(middleware.AuthMiddleware(p.AuthSvc))
	{
		util := adm.Group("/utility")
		{
			util.POST("/verify", p.Utility.Verify)
			util.POST("/parse", p.Utility.Parse)
			util.POST("/convert", p.Utility.Convert)
			util.POST("/generate-csr", p.Utility.GenerateCSR)
		}
	}

	// ── Agent routes (future) ───────────────────────────────────────────
	// agent := api.Group("/agent/cert")
	// agent.Use(agentAuthMiddleware)

	// ── Public API routes (future) ──────────────────────────────────────
	// pub := api.Group("/pub/cert")
}

func Start(lc fx.Lifecycle, s *Server) {
	srv := &http.Server{
		Addr:    fmt.Sprintf(":%s", s.cfg.Server.Port),
		Handler: s.engine,
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			s.log.Info("starting server", zap.String("addr", srv.Addr))
			go func() {
				if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					s.log.Fatal("server error", zap.Error(err))
				}
			}()
			return nil
		},
		OnStop: func(ctx context.Context) error {
			s.log.Info("stopping server")
			return srv.Shutdown(ctx)
		},
	})
}
