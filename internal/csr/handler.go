package csr

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/robert7528/hycore/middleware"
)

// Handler handles HTTP requests for CSRs.
type Handler struct {
	svc *Service
}

// NewHandler creates a new CSR Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Generate handles POST /csrs
func (h *Handler) Generate(c *gin.Context) {
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

	var req CreateCSRRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.Generate(db, &req, username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "CSR_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": dto})
}

// List handles GET /csrs
func (h *Handler) List(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	var q CSRListQuery
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

// Get handles GET /csrs/:id
func (h *Handler) Get(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid CSR ID"}})
		return
	}

	dto, err := h.svc.Get(db, uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// Delete handles DELETE /csrs/:id
func (h *Handler) Delete(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid CSR ID"}})
		return
	}

	if err := h.svc.Delete(db, uint(id)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DELETE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "CSR deleted"}})
}

// Download handles GET /csrs/:id/download
func (h *Handler) Download(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid CSR ID"}})
		return
	}

	data, filename, err := h.svc.Download(db, uint(id))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DOWNLOAD_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"format":   "pem",
			"content":  string(data),
			"filename": filename,
		},
	})
}
