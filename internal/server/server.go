package server

import (
	"context"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hysp/hycert-api/internal/acme"
	"github.com/hysp/hycert-api/internal/agent"
	"github.com/hysp/hycert-api/internal/certificate"
	"github.com/hysp/hycert-api/internal/csr"
	"github.com/hysp/hycert-api/internal/deployment"
	"github.com/hysp/hycert-api/internal/health"
	"github.com/hysp/hycert-api/internal/utility"
	coreauth "github.com/robert7528/hycore/auth"
	coreauditlog "github.com/robert7528/hycore/auditlog"
	"github.com/robert7528/hycore/config"
	"github.com/robert7528/hycore/database"
	"github.com/robert7528/hycore/middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"gorm.io/gorm"
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
	Server    *Server
	Health    *health.Handler
	AuthSvc   *coreauth.Service
	Utility   *utility.Handler
	DB        *gorm.DB
	DBManager *database.DBManager

	// CRUD handlers
	CertHandler   *certificate.Handler
	CSRHandler    *csr.Handler
	DeployHandler *deployment.Handler

	// Agent handler
	AgentHandler *agent.Handler
	AgentSvc     *agent.Service

	// ACME handler
	AcmeHandler *acme.Handler
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

	// Utility (no tenant DB needed)
	{
		util := adm.Group("/utility")
		{
			util.POST("/verify", p.Utility.Verify)
			util.POST("/parse", p.Utility.Parse)
			util.POST("/convert", p.Utility.Convert)
			util.POST("/generate-csr", p.Utility.GenerateCSR)
			util.POST("/merge-chain", p.Utility.MergeChain)
			util.POST("/decrypt-key", p.Utility.DecryptKey)
		}
	}

	// Agent Token management (JWT + admin DB, no tenant DB needed)
	{
		tokens := adm.Group("/agent-tokens")
		{
			tokens.POST("", p.AgentHandler.CreateToken)
			tokens.GET("", p.AgentHandler.ListTokens)
			tokens.GET("/labels", p.AgentHandler.ListLabels)
			tokens.GET("/by-label/:label", p.AgentHandler.GetTokenByLabel)
			tokens.GET("/:id", p.AgentHandler.GetToken)
			tokens.GET("/:id/reveal", p.AgentHandler.RevealToken)
			tokens.PUT("/:id", p.AgentHandler.UpdateToken)
			tokens.PUT("/:id/revoke", p.AgentHandler.RevokeToken)
			tokens.DELETE("/:id", p.AgentHandler.DeleteToken)
		}
	}

	// CRUD (tenant DB + audit middleware)
	// Note: agent-registrations route group is added after crud is defined (below)
	{
		crud := adm.Group("")
		crud.Use(middleware.TenantMiddleware())
		crud.Use(middleware.TenantDBMiddleware(p.DBManager))
		crud.Use(coreauditlog.AuditMiddleware(p.DB))

		// Certificates
		certs := crud.Group("/certificates")
		{
			certs.POST("", p.CertHandler.Import)
			certs.GET("", p.CertHandler.List)
			certs.GET("/:id", p.CertHandler.Get)
			certs.PUT("/:id", p.CertHandler.Update)
			certs.DELETE("/:id", p.CertHandler.Delete)
			certs.PUT("/:id/key", p.CertHandler.UploadKey)
			certs.GET("/:id/download", p.CertHandler.Download)
		}

		// CSRs
		csrs := crud.Group("/csrs")
		{
			csrs.POST("", p.CSRHandler.Generate)
			csrs.GET("", p.CSRHandler.List)
			csrs.GET("/:id", p.CSRHandler.Get)
			csrs.DELETE("/:id", p.CSRHandler.Delete)
			csrs.GET("/:id/download", p.CSRHandler.Download)
		}

		// Deployments
		deploys := crud.Group("/deployments")
		{
			deploys.POST("", p.DeployHandler.Create)
			deploys.GET("", p.DeployHandler.List)
			deploys.GET("/:id", p.DeployHandler.Get)
			deploys.PUT("/:id", p.DeployHandler.Update)
			deploys.DELETE("/:id", p.DeployHandler.Delete)
			deploys.GET("/:id/history", p.AgentHandler.GetDeploymentHistory)
		}

		// ACME DNS Providers (metadata, no DB needed)
		crud.GET("/acme/dns-providers", p.AcmeHandler.ListDNSProviders)

		// ACME Accounts
		acmeAccts := crud.Group("/acme/accounts")
		{
			acmeAccts.POST("", p.AcmeHandler.CreateAccount)
			acmeAccts.GET("", p.AcmeHandler.ListAccounts)
			acmeAccts.GET("/:id", p.AcmeHandler.GetAccount)
			acmeAccts.PUT("/:id", p.AcmeHandler.UpdateAccount)
			acmeAccts.DELETE("/:id", p.AcmeHandler.DeleteAccount)
		}

		// ACME Orders
		acmeOrders := crud.Group("/acme/orders")
		{
			acmeOrders.POST("", p.AcmeHandler.CreateOrder)
			acmeOrders.GET("", p.AcmeHandler.ListOrders)
			acmeOrders.GET("/:id", p.AcmeHandler.GetOrder)
			acmeOrders.POST("/:id/renew", p.AcmeHandler.RenewOrder)
			acmeOrders.DELETE("/:id", p.AcmeHandler.CancelOrder)
		}
		agentRegs := crud.Group("/agent-registrations")
		{
			agentRegs.GET("", p.AgentHandler.AdminListRegistrations)
			agentRegs.PUT("/:id/status", p.AgentHandler.AdminUpdateRegistrationStatus)
		}
	}

	// ── Agent routes (Agent Token auth) ─────────────────────────────────
	agentGroup := api.Group("/agent/cert")
	agentGroup.Use(agent.AgentAuthMiddleware(p.AgentSvc, p.DB, p.DBManager, p.Server.log))
	{
		agentGroup.POST("/register", p.AgentHandler.AgentRegister)
		agentGroup.GET("/deployments", p.AgentHandler.AgentGetDeployments)
		agentGroup.GET("/certificates/:id/download", p.AgentHandler.AgentDownloadCert)
		agentGroup.PUT("/deployments/:id/status", p.AgentHandler.AgentUpdateDeployStatus)
	}
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
