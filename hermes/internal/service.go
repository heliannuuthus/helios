package hermes

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/heliannuuthus/hermes/config"
)

// Service hermes 业务服务
type Service struct {
	db *gorm.DB
}

// NewService 创建 hermes 业务服务
func NewService(db *gorm.DB) (*Service, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库连接未初始化")
	}
	if _, err := config.GetDBEncKeyRaw(); err != nil {
		return nil, fmt.Errorf("数据库加密模块初始化失败: %w", err)
	}
	return &Service{db: db}, nil
}
