package chaos

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/heliannuuthus/helios/chaos/config"
	"github.com/heliannuuthus/helios/chaos/internal/mail"
	"github.com/heliannuuthus/helios/chaos/internal/storage"
	"github.com/heliannuuthus/helios/chaos/internal/template"
	"github.com/heliannuuthus/helios/chaos/models"
	"github.com/heliannuuthus/helios/pkg/logger"
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
	_ = config.Cfg()

	if err := autoMigrate(db); err != nil {
		return nil, fmt.Errorf("数据库迁移失败: %w", err)
	}

	templateSvc := template.NewService(db)

	mailSvc, err := mail.NewService(templateSvc)
	if err != nil {
		return nil, fmt.Errorf("创建邮件服务失败: %w", err)
	}

	var storageSvc *storage.Service
	if config.GetCloudflareR2Endpoint() != "" {
		storageSvc, err = storage.NewService()
		if err != nil {
			logger.Warnf("[Chaos] 创建存储服务失败（将禁用文件上传功能）: %v", err)
		}
	}

	handler := NewHandler(mailSvc, templateSvc, storageSvc)

	return &Chaos{
		handler:         handler,
		mailService:     mailSvc,
		templateService: templateSvc,
		storageService:  storageSvc,
	}, nil
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
	if c.mailService != nil {
		c.mailService.Close()
	}
}

// autoMigrate 自动迁移数据库
func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.EmailTemplate{},
	)
}
