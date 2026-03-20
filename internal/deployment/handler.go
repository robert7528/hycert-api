package deployment

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/robert7528/hycore/middleware"
)

// Handler handles HTTP requests for deployments.
type Handler struct {
	svc *Service
}

// NewHandler creates a new deployment Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Create handles POST /deployments
func (h *Handler) Create(c *gin.Context) {
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

	var req CreateDeploymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	d, err := h.svc.Create(db, &req, username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "CREATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": d})
}

// List handles GET /deployments
func (h *Handler) List(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	var q DeploymentListQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	resp, err := h.svc.List(db, &q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "LIST_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

// Get handles GET /deployments/:id
func (h *Handler) Get(c *gin.Context) {
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

	d, err := h.svc.Get(db, uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": d})
}

// Update handles PUT /deployments/:id
func (h *Handler) Update(c *gin.Context) {
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

	var req UpdateDeploymentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	d, err := h.svc.Update(db, uint(id), &req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPDATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": d})
}

// Delete handles DELETE /deployments/:id
func (h *Handler) Delete(c *gin.Context) {
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

	if err := h.svc.Delete(db, uint(id)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DELETE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "deployment deleted"}})
}
