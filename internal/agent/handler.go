package agent

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/hysp/hycert-api/internal/certificate"
	"github.com/robert7528/hycore/middleware"
	"gorm.io/gorm"
)

// Handler handles HTTP requests for agent token management and agent API.
type Handler struct {
	svc     *Service
	certSvc *certificate.Service
	adminDB *gorm.DB
}

// NewHandler creates a new agent Handler.
func NewHandler(svc *Service, certSvc *certificate.Service, adminDB *gorm.DB) *Handler {
	return &Handler{svc: svc, certSvc: certSvc, adminDB: adminDB}
}

// ── Admin Token Management Endpoints ────────────────────────────────────────

// CreateToken handles POST /adm/cert/agent-tokens
func (h *Handler) CreateToken(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	var req CreateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.CreateToken(h.adminDB, &req, claims.TenantCode, claims.Username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "CREATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": resp})
}

// ListTokens handles GET /adm/cert/agent-tokens
func (h *Handler) ListTokens(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	var q TokenListQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.ListTokens(h.adminDB, claims.TenantCode, &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "LIST_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// GetToken handles GET /adm/cert/agent-tokens/:id
func (h *Handler) GetToken(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid token ID"}})
		return
	}

	dto, err := h.svc.GetToken(h.adminDB, uint(id), claims.TenantCode)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// RevokeToken handles DELETE /adm/cert/agent-tokens/:id
func (h *Handler) RevokeToken(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid token ID"}})
		return
	}

	if err := h.svc.RevokeToken(h.adminDB, uint(id), claims.TenantCode); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "REVOKE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "token revoked"}})
}

// UpdateToken handles PUT /adm/cert/agent-tokens/:id
func (h *Handler) UpdateToken(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid token ID"}})
		return
	}

	var req UpdateTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.UpdateToken(h.adminDB, uint(id), claims.TenantCode, &req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPDATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// GetTokenByLabel handles GET /adm/cert/agent-tokens/by-label/:label
func (h *Handler) GetTokenByLabel(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	label := c.Param("label")
	resp, err := h.svc.GetTokenByLabel(h.adminDB, claims.TenantCode, label)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// ListLabels handles GET /adm/cert/agent-tokens/labels
func (h *Handler) ListLabels(c *gin.Context) {
	claims := middleware.GetClaims(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing claims"}})
		return
	}

	labels, err := h.svc.ListLabels(h.adminDB, claims.TenantCode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "LIST_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": labels})
}

// ── Admin Deployment History Endpoint ───────────────────────────────────────

// GetDeploymentHistory handles GET /adm/cert/deployments/:id/history
func (h *Handler) GetDeploymentHistory(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid deployment ID"}})
		return
	}

	var q HistoryListQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.GetDeploymentHistory(db, uint(id), &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "HISTORY_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// ── Agent API Endpoints ─────────────────────────────────────────────────────

// AgentGetDeployments handles GET /agent/cert/deployments
// AgentGetDeployments handles GET /agent/cert/deployments
// Requires X-Agent-ID header to identify the agent.
func (h *Handler) AgentGetDeployments(c *gin.Context) {
	db := GetAgentTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	agentID := c.GetHeader("X-Agent-ID")
	if agentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": "X-Agent-ID header is required"}})
		return
	}

	// Get token label for deployment filtering
	tokenLabel := ""
	if token := GetAgentToken(c); token != nil {
		tokenLabel = token.Label
	}

	deployments, err := h.svc.GetDeploymentsByAgentID(db, agentID, tokenLabel)
	if err != nil {
		if err.Error() == "agent is disabled" {
			c.JSON(http.StatusForbidden, gin.H{"success": false, "error": gin.H{"code": "AGENT_DISABLED", "message": err.Error()}})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "QUERY_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": deployments})
}

// AgentDownloadCert handles GET /agent/cert/certificates/:id/download?format=...
// Reuses the existing certificate.Service.Download logic.
func (h *Handler) AgentDownloadCert(c *gin.Context) {
	db := GetAgentTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid certificate ID"}})
		return
	}

	var q certificate.DownloadQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	result, err := h.certSvc.Download(db, uint(id), &q)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DOWNLOAD_FAILED", "message": err.Error()}})
		return
	}

	// Return PEM as text, binary formats as base64
	if result.Format == "pem" || result.Format == "key" {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"format":   result.Format,
				"content":  string(result.Data),
				"filename": result.FilenameSugg,
			},
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"format":         result.Format,
				"content_base64": result.Data,
				"filename":       result.FilenameSugg,
			},
		})
	}
}

// AgentUpdateDeployStatus handles PUT /agent/cert/deployments/:id/status
func (h *Handler) AgentUpdateDeployStatus(c *gin.Context) {
	db := GetAgentTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	token := GetAgentToken(c)
	if token == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing agent token"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid deployment ID"}})
		return
	}

	var req UpdateDeployStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	if err := h.svc.UpdateDeployStatus(db, uint(id), token.ID, &req); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPDATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "deploy status updated"}})
}

// ── Agent Registration Endpoints ─────────────────────────────────────────────

// AgentRegister handles POST /agent/cert/register
func (h *Handler) AgentRegister(c *gin.Context) {
	db := GetAgentTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	token := GetAgentToken(c)
	if token == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": gin.H{"code": "UNAUTHORIZED", "message": "missing agent token"}})
		return
	}

	var req RegisterAgentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.RegisterAgent(db, token.ID, &req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "REGISTER_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// AdminUpdateRegistrationStatus handles PUT /adm/cert/agent-registrations/:id/status
func (h *Handler) AdminUpdateRegistrationStatus(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid agent ID"}})
		return
	}

	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	if err := h.svc.UpdateRegistrationStatus(db, uint(id), req.Status); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPDATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "agent status updated"}})
}

// AdminListRegistrations handles GET /adm/cert/agent-registrations
func (h *Handler) AdminListRegistrations(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	var q AgentRegistrationListQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.ListRegistrations(db, &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "LIST_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}
