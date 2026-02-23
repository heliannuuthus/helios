package chaos

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/heliannuuthus/helios/chaos/internal/mail"
	"github.com/heliannuuthus/helios/chaos/internal/storage"
	"github.com/heliannuuthus/helios/chaos/internal/template"
	"github.com/heliannuuthus/helios/chaos/models"
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

		// 文件上传（暂不落库，等 Worker 方案确定后再实现访问控制）
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
