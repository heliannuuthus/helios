package hermes

import (
	"gorm.io/gorm"
)

// Service hermes 业务服务
type Service struct {
	db *gorm.DB
}

// NewService 创建 hermes 业务服务
func NewService(db *gorm.DB) *Service {
	return &Service{db: db}
}
