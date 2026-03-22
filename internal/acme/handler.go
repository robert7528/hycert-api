package acme

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/robert7528/hycore/middleware"
)

// Handler handles HTTP requests for ACME operations.
type Handler struct {
	svc *Service
}

// NewHandler creates a new ACME Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// ── Account Endpoints ───────────────────────────────────────────────────────

// CreateAccount handles POST /adm/cert/acme/accounts
func (h *Handler) CreateAccount(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}
	claims := middleware.GetClaims(c)
	username := ""
	if claims != nil {
		username = claims.Username
	}

	var req CreateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.CreateAccount(db, &req, username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "CREATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": dto})
}

// ListAccounts handles GET /adm/cert/acme/accounts
func (h *Handler) ListAccounts(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	var q AccountListQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.ListAccounts(db, &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "LIST_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// GetAccount handles GET /adm/cert/acme/accounts/:id
func (h *Handler) GetAccount(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid account ID"}})
		return
	}

	dto, err := h.svc.GetAccount(db, uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// UpdateAccount handles PUT /adm/cert/acme/accounts/:id
func (h *Handler) UpdateAccount(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid account ID"}})
		return
	}

	var req UpdateAccountRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.UpdateAccount(db, uint(id), &req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPDATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// DeleteAccount handles DELETE /adm/cert/acme/accounts/:id
func (h *Handler) DeleteAccount(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid account ID"}})
		return
	}

	if err := h.svc.DeleteAccount(db, uint(id)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DELETE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "account deleted"}})
}

// ── Order Endpoints ─────────────────────────────────────────────────────────

// CreateOrder handles POST /adm/cert/acme/orders
func (h *Handler) CreateOrder(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}
	claims := middleware.GetClaims(c)
	username := ""
	if claims != nil {
		username = claims.Username
	}

	var req CreateOrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.CreateOrder(db, &req, username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "CREATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": dto})
}

// ListOrders handles GET /adm/cert/acme/orders
func (h *Handler) ListOrders(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	var q OrderListQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.ListOrders(db, &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "LIST_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// GetOrder handles GET /adm/cert/acme/orders/:id
func (h *Handler) GetOrder(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid order ID"}})
		return
	}

	dto, err := h.svc.GetOrder(db, uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// RenewOrder handles POST /adm/cert/acme/orders/:id/renew
func (h *Handler) RenewOrder(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid order ID"}})
		return
	}

	dto, err := h.svc.RenewOrder(db, uint(id))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "RENEW_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// CancelOrder handles DELETE /adm/cert/acme/orders/:id
func (h *Handler) CancelOrder(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid order ID"}})
		return
	}

	if err := h.svc.CancelOrder(db, uint(id)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "CANCEL_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "order cancelled"}})
}
