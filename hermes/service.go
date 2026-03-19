package hermes

import (
	"gorm.io/gorm"
)

// UserService 用户、身份、凭证、组相关业务
type UserService struct {
	db *gorm.DB
}

// NewUserService 创建用户服务
func NewUserService(db *gorm.DB) *UserService {
	return &UserService{db: db}
}

// ProvisionService 域、服务、应用、IDP 配置相关业务
type ProvisionService struct {
	db     *gorm.DB
	keySvc *KeyService
}

// NewProvisionService 创建配置服务
func NewProvisionService(db *gorm.DB, keySvc *KeyService) *ProvisionService {
	return &ProvisionService{db: db, keySvc: keySvc}
}

// ResourceService 关系、应用服务关联相关业务
type ResourceService struct {
	db *gorm.DB
}

// NewResourceService 创建资源服务
func NewResourceService(db *gorm.DB) *ResourceService {
	return &ResourceService{db: db}
}

// KeyService 密钥管理相关业务
type KeyService struct {
	db *gorm.DB
}

// NewKeyService 创建密钥服务
func NewKeyService(db *gorm.DB) *KeyService {
	return &KeyService{db: db}
}
