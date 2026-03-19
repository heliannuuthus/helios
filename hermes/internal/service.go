package hermes

import (
	"fmt"

	"gorm.io/gorm"

	"github.com/heliannuuthus/hermes/config"
)

// Services 聚合 Hermes 各领域服务。
type Services struct {
	User      *UserService
	Provision *ProvisionService
	Resource  *ResourceService
	Key       *KeyService
}

// UserService 负责用户、身份、凭证和用户组。
type UserService struct {
	db *gorm.DB
}

// ProvisionService 负责域、服务、应用和 IDP 配置。
type ProvisionService struct {
	db     *gorm.DB
	keySvc *KeyService
}

// ResourceService 负责关系和应用服务关联。
type ResourceService struct {
	db *gorm.DB
}

// KeyService 负责密钥管理。
type KeyService struct {
	db *gorm.DB
}

// NewServices 创建并校验 Hermes 领域服务。
func NewServices(db *gorm.DB) (*Services, error) {
	if db == nil {
		return nil, fmt.Errorf("数据库连接未初始化")
	}
	if _, err := config.GetDBEncKeyRaw(); err != nil {
		return nil, fmt.Errorf("数据库加密模块初始化失败: %w", err)
	}

	keySvc := &KeyService{db: db}
	return &Services{
		User:      &UserService{db: db},
		Provision: &ProvisionService{db: db, keySvc: keySvc},
		Resource:  &ResourceService{db: db},
		Key:       keySvc,
	}, nil
}
