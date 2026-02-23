package template

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"sync"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/chaos/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// Service 模板服务
type Service struct {
	db        *gorm.DB
	templates sync.Map // template_id -> *template.Template (缓存)
}

// NewService 创建模板服务
func NewService(db *gorm.DB) *Service {
	return &Service{
		db: db,
	}
}

// Create 创建模板
func (s *Service) Create(ctx context.Context, req *CreateRequest) (*models.EmailTemplate, error) {
	tpl := &models.EmailTemplate{
		TemplateID:  req.TemplateID,
		Name:        req.Name,
		Description: req.Description,
		Subject:     req.Subject,
		Content:     req.Content,
		Type:        "html",
		Variables:   req.Variables,
		ServiceID:   req.ServiceID,
		IsBuiltin:   false,
		IsEnabled:   true,
	}

	if err := s.db.WithContext(ctx).Create(tpl).Error; err != nil {
		return nil, fmt.Errorf("创建模板失败: %w", err)
	}

	return tpl, nil
}

// Get 获取模板
func (s *Service) Get(ctx context.Context, templateID string) (*models.EmailTemplate, error) {
	var tpl models.EmailTemplate
	if err := s.db.WithContext(ctx).
		Where("template_id = ? AND deleted_at IS NULL", templateID).
		First(&tpl).Error; err != nil {
		return nil, fmt.Errorf("获取模板失败: %w", err)
	}
	return &tpl, nil
}

// List 列出模板
func (s *Service) List(ctx context.Context, serviceID *string) ([]models.EmailTemplate, error) {
	var templates []models.EmailTemplate
	query := s.db.WithContext(ctx).Where("deleted_at IS NULL")
	if serviceID != nil {
		query = query.Where("service_id = ? OR service_id IS NULL", *serviceID)
	}
	if err := query.Order("created_at DESC").Find(&templates).Error; err != nil {
		return nil, fmt.Errorf("列出模板失败: %w", err)
	}
	return templates, nil
}

// Update 更新模板
func (s *Service) Update(ctx context.Context, templateID string, req *UpdateRequest) error {
	updates := make(map[string]any)
	if req.Name != nil {
		updates["name"] = *req.Name
	}
	if req.Description != nil {
		updates["description"] = *req.Description
	}
	if req.Subject != nil {
		updates["subject"] = *req.Subject
	}
	if req.Content != nil {
		updates["content"] = *req.Content
	}
	if req.Variables != nil {
		updates["variables"] = *req.Variables
	}
	if req.IsEnabled != nil {
		updates["is_enabled"] = *req.IsEnabled
	}

	if len(updates) == 0 {
		return nil
	}

	if err := s.db.WithContext(ctx).Model(&models.EmailTemplate{}).
		Where("template_id = ? AND deleted_at IS NULL AND is_builtin = false", templateID).
		Updates(updates).Error; err != nil {
		return fmt.Errorf("更新模板失败: %w", err)
	}

	s.templates.Delete(templateID)

	return nil
}

// Delete 删除模板（软删除）
func (s *Service) Delete(ctx context.Context, templateID string) error {
	result := s.db.WithContext(ctx).Model(&models.EmailTemplate{}).
		Where("template_id = ? AND is_builtin = false", templateID).
		Update("deleted_at", gorm.Expr("NOW()"))

	if result.Error != nil {
		return fmt.Errorf("删除模板失败: %w", result.Error)
	}

	s.templates.Delete(templateID)

	return nil
}

// Render 渲染模板
func (s *Service) Render(ctx context.Context, templateID string, data map[string]any) (subject string, body string, err error) {
	tpl, err := s.Get(ctx, templateID)
	if err != nil {
		return "", "", err
	}

	if !tpl.IsEnabled {
		return "", "", fmt.Errorf("模板已禁用: %s", templateID)
	}

	parsedTpl, err := s.getOrParseTemplate(tpl)
	if err != nil {
		return "", "", fmt.Errorf("解析模板失败: %w", err)
	}

	var buf bytes.Buffer
	if err := parsedTpl.Execute(&buf, data); err != nil {
		return "", "", fmt.Errorf("渲染模板失败: %w", err)
	}

	subjectTpl, err := template.New("subject").Parse(tpl.Subject)
	if err != nil {
		return tpl.Subject, buf.String(), nil
	}

	var subjectBuf bytes.Buffer
	if err := subjectTpl.Execute(&subjectBuf, data); err != nil {
		logger.Warnf("[Template] 渲染主题失败: %v", err)
		return tpl.Subject, buf.String(), nil
	}

	return subjectBuf.String(), buf.String(), nil
}

// getOrParseTemplate 获取或解析模板
func (s *Service) getOrParseTemplate(tpl *models.EmailTemplate) (*template.Template, error) {
	if cached, ok := s.templates.Load(tpl.TemplateID); ok {
		return cached.(*template.Template), nil
	}

	parsed, err := template.New(tpl.TemplateID).Parse(tpl.Content)
	if err != nil {
		return nil, err
	}

	s.templates.Store(tpl.TemplateID, parsed)
	return parsed, nil
}
