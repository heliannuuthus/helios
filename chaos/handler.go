package chaos

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/heliannuuthus/aegis-go/guard"
	reqr "github.com/heliannuuthus/aegis-go/guard/requirement"
	"github.com/heliannuuthus/aegis-go/utilities/relation"

	"github.com/heliannuuthus/helios/chaos/internal/mail"
	"github.com/heliannuuthus/helios/chaos/internal/storage"
	"github.com/heliannuuthus/helios/chaos/internal/template"
	"github.com/heliannuuthus/helios/chaos/models"
)

// Handler Chaos API Handler
type Handler struct {
	guard           *guard.Gin
	audience        string
	mailService     *mail.Service
	templateService *template.Service
	storageService  *storage.Service
}

// NewHandler 创建 Handler
func NewHandler(g *guard.Gin, audience string, mailSvc *mail.Service, templateSvc *template.Service, storageSvc *storage.Service) *Handler {
	return &Handler{
		guard:           g,
		audience:        audience,
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

// PresignUpload 生成 Presigned URL POST /chaos/presign
func (h *Handler) PresignUpload(c *gin.Context) {
	if h.storageService == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "文件存储服务未配置"})
		return
	}

	var req storage.PresignRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("参数错误: %v", err)})
		return
	}

	resp, err := h.storageService.GeneratePresignedURL(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "生成上传链接失败"})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// RegisterRoutes 注册路由
func (h *Handler) RegisterRoutes(r gin.IRouter) {
	svc := "service:" + h.audience

	chaos := r.Group("/chaos")
	chaos.Use(h.guard.Require())
	{
		chaos.POST("/mail", h.SendMail)

		templates := chaos.Group("/templates")
		templates.Use(h.guard.Require(reqr.Relation(relation.Qualify("admin", svc))))
		{
			templates.POST("", h.CreateTemplate)
			templates.GET("", h.ListTemplates)
			templates.GET("/:id", h.GetTemplate)
			templates.PATCH("/:id", h.UpdateTemplate)
			templates.DELETE("/:id", h.DeleteTemplate)
			templates.POST("/:id/render", h.RenderTemplate)
		}

		chaos.POST("/presign", h.guard.Require(reqr.User(), reqr.Relation(relation.Qualify("editor", svc))), h.PresignUpload)
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
