package user

import (
	"context"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	autherrors "github.com/heliannuuthus/helios/internal/aegis/errors"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/internal/hermes/models"
)

// Service 用户业务服务
// 封装用户领域的业务逻辑：
//   - 缓存读取委托 cache.Manager（read-through）
//   - 非缓存的 DB 操作直接调用 hermes.UserService
type Service struct {
	cache   *cache.Manager
	userSvc *hermes.UserService
}

// NewService 创建用户业务服务
func NewService(cache *cache.Manager, userSvc *hermes.UserService) *Service {
	return &Service{
		cache:   cache,
		userSvc: userSvc,
	}
}

// GetUser 按 OpenID 获取用户（委托 cache read-through）
func (s *Service) GetUser(ctx context.Context, openid string) (*models.UserWithDecrypted, error) {
	return s.cache.GetUser(ctx, openid)
}

// GetIdentityTypes 获取用户已绑定的身份类型列表
func (s *Service) GetIdentityTypes(ctx context.Context, openid string) ([]string, error) {
	identities, err := s.userSvc.GetIdentities(ctx, openid)
	if err != nil {
		return nil, err
	}
	return identities.IDPTypes(), nil
}

// GetIdentities 通过身份查找该用户的全部身份
// 用户不存在返回空切片，仅基础设施故障返回 error
func (s *Service) GetIdentities(ctx context.Context, identity *models.UserIdentity) (models.Identities, error) {
	return s.userSvc.GetIdentitiesByIdentity(ctx, identity)
}

// UpdateLastLogin 更新最后登录时间
func (s *Service) UpdateLastLogin(ctx context.Context, openid string) error {
	return s.userSvc.UpdateLastLogin(ctx, openid)
}

// CreateUser 创建用户，返回全部身份
func (s *Service) CreateUser(ctx context.Context, identity *models.UserIdentity, userInfo *models.TUserInfo) (models.Identities, error) {
	newUser, err := s.userSvc.CreateUser(ctx, identity, userInfo)
	if err != nil {
		return nil, autherrors.NewServerError("user creation failed")
	}

	s.cache.CacheUser(newUser)

	return s.userSvc.GetIdentities(ctx, newUser.OpenID)
}
