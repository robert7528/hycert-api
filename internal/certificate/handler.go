package certificate

import (
	"encoding/base64"
	"math"
	"net/http"
	"strconv"
	"time"


	"github.com/gin-gonic/gin"
	"github.com/robert7528/hycore/middleware"
)

// Handler handles HTTP requests for certificates.
type Handler struct {
	svc *Service
}

// NewHandler creates a new certificate Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Import handles POST /certificates
func (h *Handler) Import(c *gin.Context) {
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

	var req ImportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	result, err := h.svc.Import(db, &req, username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "IMPORT_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"success": true, "data": result.Certificate, "warnings": result.Warnings})
}

// List handles GET /certificates
func (h *Handler) List(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	var q ListQuery
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

// Get handles GET /certificates/:id
func (h *Handler) Get(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid certificate ID"}})
		return
	}

	dto, err := h.svc.Get(db, uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": gin.H{"code": "NOT_FOUND", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// Update handles PUT /certificates/:id
func (h *Handler) Update(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid certificate ID"}})
		return
	}

	var req UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.Update(db, uint(id), &req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPDATE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// UploadKey handles PUT /certificates/:id/key
func (h *Handler) UploadKey(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid certificate ID"}})
		return
	}

	var req UploadKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	dto, err := h.svc.UploadKey(db, uint(id), &req)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "UPLOAD_KEY_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": dto})
}

// Delete handles DELETE /certificates/:id
func (h *Handler) Delete(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid certificate ID"}})
		return
	}

	if err := h.svc.Delete(db, uint(id)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DELETE_FAILED", "message": err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"message": "certificate deleted"}})
}

// Download handles GET /certificates/:id/download
func (h *Handler) Download(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_ID", "message": "invalid certificate ID"}})
		return
	}

	var q DownloadQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": gin.H{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}

	result, err := h.svc.Download(db, uint(id), &q)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"success": false, "error": gin.H{"code": "DOWNLOAD_FAILED", "message": err.Error()}})
		return
	}

	// For PEM format, return as text; for binary formats, return base64
	if result.Format == "pem" {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"format":            result.Format,
				"content":           string(result.Data),
				"filename":          result.FilenameSugg,
				"chain_included":    result.ChainIncluded,
			},
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"data": gin.H{
				"format":            result.Format,
				"content_base64":    base64.StdEncoding.EncodeToString(result.Data),
				"filename":          result.FilenameSugg,
				"chain_included":    result.ChainIncluded,
			},
		})
	}
}

// ExpiringWarnings handles GET /certificates/expiring?days=30
func (h *Handler) ExpiringWarnings(c *gin.Context) {
	db := middleware.GetTenantDB(c)
	if db == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"success": false, "error": gin.H{"code": "DB_UNAVAILABLE", "message": "tenant database unavailable"}})
		return
	}

	days := 30
	if d, err := strconv.Atoi(c.DefaultQuery("days", "30")); err == nil && d > 0 {
		days = d
	}

	dtos, err := h.svc.FindExpiringSoon(db, days)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": gin.H{"code": "QUERY_FAILED", "message": err.Error()}})
		return
	}

	// Add days_remaining to each item
	type expiringCert struct {
		CertificateDTO
		DaysRemaining int `json:"days_remaining"`
	}
	items := make([]expiringCert, 0, len(dtos))
	for _, d := range dtos {
		remaining := 0
		if d.NotAfter != nil {
			remaining = int(math.Ceil(time.Until(*d.NotAfter).Hours() / 24))
		}
		items = append(items, expiringCert{CertificateDTO: d, DaysRemaining: remaining})
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"items": items, "total": len(items)}})
}
