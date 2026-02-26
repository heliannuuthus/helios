package chaos

import (
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/chaos/internal/mail"
	"github.com/heliannuuthus/helios/chaos/internal/storage"
	"github.com/heliannuuthus/helios/chaos/internal/template"
	"github.com/heliannuuthus/helios/chaos/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Handler Chaos API Handler
type Handler struct {
	mailService     *mail.Service
	templateService *template.Service
	storageService  *storage.Service
}

// NewHandler 创建 Handler
func NewHandler(mailSvc *mail.Service, templateSvc *template.Service, storageSvc *storage.Service) *Handler {
	return &Handler{
		mailService:     mailSvc,
		templateService: templateSvc,
		storageService:  storageSvc,
	}
}

// SendMail 发送邮件 POST /chaos/mail
func (h *Handler) SendMail(c *gin.Context) {
	var req mail.SendRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.mailService.Send(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "邮件发送成功"})
}

// CreateTemplate 创建模板 POST /chaos/templates
func (h *Handler) CreateTemplate(c *gin.Context) {
	var req template.CreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tpl, err := h.templateService.Create(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, tpl)
}

// GetTemplate 获取模板 GET /chaos/templates/:id
func (h *Handler) GetTemplate(c *gin.Context) {
	templateID := c.Param("id")

	tpl, err := h.templateService.Get(c.Request.Context(), templateID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, tpl)
}

// ListTemplates 列出模板 GET /chaos/templates
func (h *Handler) ListTemplates(c *gin.Context) {
	var serviceID *string
	if sid := c.Query("service_id"); sid != "" {
		serviceID = &sid
	}

	templates, err := h.templateService.List(c.Request.Context(), serviceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, templates)
}

// UpdateTemplate 更新模板 PATCH /chaos/templates/:id
func (h *Handler) UpdateTemplate(c *gin.Context) {
	templateID := c.Param("id")

	var req template.UpdateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.templateService.Update(c.Request.Context(), templateID, &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "模板更新成功"})
}

// DeleteTemplate 删除模板 DELETE /chaos/templates/:id
func (h *Handler) DeleteTemplate(c *gin.Context) {
	templateID := c.Param("id")

	if err := h.templateService.Delete(c.Request.Context(), templateID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// RenderTemplate 预览渲染模板 POST /chaos/templates/:id/render
func (h *Handler) RenderTemplate(c *gin.Context) {
	templateID := c.Param("id")

	var req struct {
		Data map[string]any `json:"data"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	subject, body, err := h.templateService.Render(c.Request.Context(), templateID, req.Data)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, template.RenderResponse{
		Subject: subject,
		Body:    body,
	})
}

// UploadImageRequest 图片上传请求参数
type UploadImageRequest struct {
	Path   string `form:"path" binding:"omitempty,max=512"`  // 完整路径，如 "avatars/user123.jpg"
	Prefix string `form:"prefix" binding:"omitempty,max=64"` // 路径前缀，如 "avatars", "images"
}

// UploadImageResponse 图片上传响应
type UploadImageResponse struct {
	URL string `json:"url"`
}

// UploadImage 上传图片 POST /chaos/upload
func (h *Handler) UploadImage(c *gin.Context) {
	if h.storageService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "文件存储服务未配置"})
		return
	}

	var req UploadImageRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("参数错误: %v", err)})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要上传的文件"})
		return
	}

	if !validateImageFile(c, file) {
		return
	}

	path := resolveUploadPath(req, file.Filename)

	result, err := h.storageService.Upload(c.Request.Context(), file, path)
	if err != nil {
		logger.Errorf("[Upload] 上传失败 - Path: %s, Error: %v", path, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "上传文件失败"})
		return
	}

	logger.Infof("[Upload] 上传成功 - URL: %s", result.PublicURL)
	c.JSON(http.StatusOK, UploadImageResponse{URL: result.PublicURL})
}

func validateImageFile(c *gin.Context, file *multipart.FileHeader) bool {
	if file.Size > 5*1024*1024 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "图片大小不能超过 5MB"})
		return false
	}

	contentType := file.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "只支持上传图片文件"})
		return false
	}

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取文件失败"})
		return false
	}
	defer func() {
		if closeErr := src.Close(); closeErr != nil {
			logger.Warnf("[Upload] close file for magic bytes check failed: %v", closeErr)
		}
	}()

	header := make([]byte, 512)
	n, err := src.Read(header)
	if err != nil && n == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取文件头失败"})
		return false
	}
	detectedType := http.DetectContentType(header[:n])
	if !strings.HasPrefix(detectedType, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "文件内容不是有效的图片格式"})
		return false
	}

	return true
}

func resolveUploadPath(req UploadImageRequest, filename string) string {
	if req.Path != "" {
		return req.Path
	}
	prefix := req.Prefix
	if prefix == "" {
		prefix = "images"
	}
	now := time.Now()
	return fmt.Sprintf("%s/%04d/%02d/%02d/%s", prefix, now.Year(), now.Month(), now.Day(), filename)
}

// UploadFile 上传文件 POST /chaos/files
// 参数: file (multipart), path (可选，指定上传路径)
func (h *Handler) UploadFile(c *gin.Context) {
	if h.storageService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "文件存储服务未配置"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "文件上传失败: " + err.Error()})
		return
	}

	// 可选：指定上传路径
	path := c.PostForm("path")

	result, err := h.storageService.Upload(c.Request.Context(), file, path)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, storage.UploadResponse{
		Key:         result.Key,
		FileName:    result.FileName,
		FileSize:    result.FileSize,
		ContentType: result.ContentType,
		PublicURL:   result.PublicURL,
	})
}

// RegisterRoutes 注册路由
func (h *Handler) RegisterRoutes(r gin.IRouter) {
	chaos := r.Group("/chaos")
	{
		chaos.POST("/mail", h.SendMail)

		templates := chaos.Group("/templates")
		{
			templates.POST("", h.CreateTemplate)
			templates.GET("", h.ListTemplates)
			templates.GET("/:id", h.GetTemplate)
			templates.PATCH("/:id", h.UpdateTemplate)
			templates.DELETE("/:id", h.DeleteTemplate)
			templates.POST("/:id/render", h.RenderTemplate)
		}

		chaos.POST("/upload", h.UploadImage)
		chaos.POST("/files", h.UploadFile)
	}
}

// MailService 获取邮件服务（供 Aegis 等内部调用）
func (h *Handler) MailService() *mail.Service {
	return h.mailService
}

// TemplateService 获取模板服务（供内部调用）
func (h *Handler) TemplateService() *template.Service {
	return h.templateService
}

// StorageService 获取存储服务（供内部调用）
func (h *Handler) StorageService() *storage.Service {
	return h.storageService
}

// Re-export types for external use
type (
	EmailTemplate  = models.EmailTemplate
	SendMailReq    = mail.SendRequest
	TemplateCreate = template.CreateRequest
	TemplateUpdate = template.UpdateRequest
)
