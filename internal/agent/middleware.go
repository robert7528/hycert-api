package agent

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/robert7528/hycore/database"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

const (
	agentTokenKey  = "agent_token"
	agentTenantDB  = "agent_tenant_db"
)

// GetAgentToken retrieves the authenticated agent token from context.
func GetAgentToken(c *gin.Context) *AgentToken {
	v, exists := c.Get(agentTokenKey)
	if !exists {
		return nil
	}
	return v.(*AgentToken)
}

// GetAgentTenantDB retrieves the tenant DB resolved by agent middleware from context.
func GetAgentTenantDB(c *gin.Context) *gorm.DB {
	v, exists := c.Get(agentTenantDB)
	if !exists {
		return nil
	}
	return v.(*gorm.DB)
}

// AgentAuthMiddleware validates the Agent Token and resolves the tenant DB.
func AgentAuthMiddleware(svc *Service, adminDB *gorm.DB, dbMgr *database.DBManager, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract Bearer token
		auth := c.GetHeader("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   gin.H{"code": "UNAUTHORIZED", "message": "missing or invalid Authorization header"},
			})
			return
		}
		rawToken := strings.TrimPrefix(auth, "Bearer ")

		// Authenticate token
		token, err := svc.Authenticate(adminDB, rawToken)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"success": false,
				"error":   gin.H{"code": "UNAUTHORIZED", "message": err.Error()},
			})
			return
		}

		// Check allowed_hosts restriction (only for legacy host-based mode)
		agentID := c.GetHeader("X-Agent-ID")
		host := c.Query("host")
		if agentID == "" && host != "" && token.AllowedHosts != "" && token.AllowedHosts != "[]" {
			var allowed []string
			if err := json.Unmarshal([]byte(token.AllowedHosts), &allowed); err == nil && len(allowed) > 0 {
				found := false
				for _, h := range allowed {
					if h == host {
						found = true
						break
					}
				}
				if !found {
					c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
						"success": false,
						"error":   gin.H{"code": "FORBIDDEN", "message": "host not in allowed_hosts for this token"},
					})
					return
				}
			}
		}

		// Resolve tenant DB
		tenantDB, err := dbMgr.GetDB(token.TenantCode)
		if err != nil {
			log.Error("failed to resolve tenant DB for agent",
				zap.String("tenant_code", token.TenantCode),
				zap.Error(err),
			)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"success": false,
				"error":   gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"},
			})
			return
		}

		c.Set(agentTokenKey, token)
		c.Set(agentTenantDB, tenantDB.WithContext(c.Request.Context()))
		c.Next()
	}
}
