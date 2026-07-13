package chaos

import (
	"context"
	"fmt"
	"time"

	"gorm.io/gorm"

	"github.com/heliannuuthus/chaos/config"
	"github.com/heliannuuthus/chaos/internal/mail"
	"github.com/heliannuuthus/chaos/internal/models"
	"github.com/heliannuuthus/chaos/internal/storage"
	"github.com/heliannuuthus/chaos/internal/template"
	"github.com/heliannuuthus/pkg/aegis/guard"
)

// Chaos 模块实例
type Chaos struct {
	handler         *Handler
	mailService     *mail.Service
	templateService *template.Service
	storageService  *storage.Service
}

// New 创建 Chaos 实例
func New(db *gorm.DB) (*Chaos, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库连接未初始化")
	}

	if err := autoMigrate(db); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	templateSvc := template.NewService(db)

	mailSvc, err := mail.NewService(templateSvc)
	if err != nil {
		return nil, fmt.Errorf("创建邮件服务失败: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := mailSvc.Verify(ctx); err != nil {
		mailSvc.Close()
		return nil, fmt.Errorf("验证邮件服务失败: %w", err)
	}

	storageSvc, err := storage.NewService()
	if err != nil {
		mailSvc.Close()
		return nil, fmt.Errorf("创建存储服务失败: %w", err)
	}
	if err := storageSvc.Verify(ctx); err != nil {
		mailSvc.Close()
		return nil, fmt.Errorf("验证存储服务失败: %w", err)
	}

	aud := config.GetAegisAudience()
	g, err := guard.NewGin(aud)
	if err != nil {
		mailSvc.Close()
		return nil, fmt.Errorf("创建鉴权中间件失败: %w", err)
	}
	handler := NewHandler(g, aud, mailSvc, templateSvc, storageSvc)

	return &Chaos{
		handler:         handler,
		mailService:     mailSvc,
		templateService: templateSvc,
		storageService:  storageSvc,
	}, nil
}

// autoMigrate 自动迁移数据库
func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.EmailTemplate{},
	)
}

// Handler 获取 HTTP Handler
func (c *Chaos) Handler() *Handler {
	return c.handler
}

// MailService 获取邮件服务（供 Aegis 等内部包调用）
func (c *Chaos) MailService() *mail.Service {
	return c.mailService
}

// TemplateService 获取模板服务
func (c *Chaos) TemplateService() *template.Service {
	return c.templateService
}

// StorageService 获取存储服务
func (c *Chaos) StorageService() *storage.Service {
	return c.storageService
}

// Close 关闭服务
func (c *Chaos) Close() {
	c.mailService.Close()
}
