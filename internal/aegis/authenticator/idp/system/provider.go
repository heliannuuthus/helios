package system

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/heliannuuthus/helios/internal/aegis/authenticator/idp"
	"github.com/heliannuuthus/helios/internal/aegis/types"
	"github.com/heliannuuthus/helios/internal/hermes"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// CredentialStore 凭证存储接口
type CredentialStore interface {
	GetByIdentifier(ctx context.Context, identifier string) (*Credential, error)
}

// Credential 凭证信息
type Credential struct {
	OpenID       string
	PasswordHash string
	Nickname     string
	Email        string
	Picture      string
	Status       int8
}

// Provider 系统账号密码 Provider
// 注意：这是一个纯登录入口，不支持注册
type Provider struct {
	idpType string
	store   CredentialStore
}

// NewUserProvider 创建 C 端用户账号密码 Provider
func NewUserProvider(userSvc *hermes.UserService) *Provider {
	return &Provider{
		idpType: idp.TypeUser,
		store:   &userCredentialStore{userSvc: userSvc},
	}
}

// NewOperProvider 创建 B 端运营人员账号密码 Provider
func NewOperProvider(userSvc *hermes.UserService) *Provider {
	return &Provider{
		idpType: idp.TypeOper,
		store:   &operCredentialStore{userSvc: userSvc},
	}
}

// userCredentialStore C 端用户凭证存储
type userCredentialStore struct {
	userSvc *hermes.UserService
}

func (s *userCredentialStore) GetByIdentifier(ctx context.Context, identifier string) (*Credential, error) {
	cred, err := s.userSvc.GetUserByIdentifier(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return &Credential{
		OpenID:       cred.OpenID,
		PasswordHash: cred.PasswordHash,
		Nickname:     cred.Nickname,
		Email:        cred.Email,
		Picture:      cred.Picture,
		Status:       cred.Status,
	}, nil
}

// operCredentialStore B 端运营人员凭证存储
type operCredentialStore struct {
	userSvc *hermes.UserService
}

func (s *operCredentialStore) GetByIdentifier(ctx context.Context, identifier string) (*Credential, error) {
	cred, err := s.userSvc.GetOperByIdentifier(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return &Credential{
		OpenID:       cred.OpenID,
		PasswordHash: cred.PasswordHash,
		Nickname:     cred.Nickname,
		Email:        cred.Email,
		Picture:      cred.Picture,
		Status:       cred.Status,
	}, nil
}

// Type 返回 IDP 类型
func (p *Provider) Type() string {
	return p.idpType
}

// Exchange 验证账号密码
// proof: password (明文密码)
// params[0]: identifier (用户名/邮箱/手机号)
func (p *Provider) Login(ctx context.Context, proof string, params ...any) (*idp.LoginResult, error) {
	if proof == "" {
		return nil, errors.New("password is required")
	}

	if len(params) < 1 {
		return nil, errors.New("identifier is required")
	}

	identifier, ok := params[0].(string)
	if !ok || identifier == "" {
		return nil, errors.New("identifier must be a non-empty string")
	}

	logger.Infof("[%s] 登录请求 - Identifier: %s", p.idpType, maskIdentifier(identifier))

	return p.login(ctx, identifier, proof)
}

// login 登录
func (p *Provider) login(ctx context.Context, identifier, password string) (*idp.LoginResult, error) {
	if p.store == nil {
		return nil, errors.New("credential store not configured")
	}

	// 1. 获取凭证
	cred, err := p.store.GetByIdentifier(ctx, identifier)
	if err != nil {
		logger.Warnf("[%s] 用户不存在 - Identifier: %s, Error: %v", p.idpType, maskIdentifier(identifier), err)
		return nil, errors.New("invalid credentials")
	}

	// 2. 检查用户状态
	if cred.Status != 0 {
		logger.Warnf("[%s] 用户已禁用 - Identifier: %s", p.idpType, maskIdentifier(identifier))
		return nil, errors.New("user is disabled")
	}

	// 3. 检查是否设置了密码
	if cred.PasswordHash == "" {
		logger.Warnf("[%s] 用户未设置密码 - Identifier: %s", p.idpType, maskIdentifier(identifier))
		return nil, errors.New("password not set, please use other login methods")
	}

	// 4. 验证密码
	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(password)); err != nil {
		logger.Warnf("[%s] 密码错误 - Identifier: %s", p.idpType, maskIdentifier(identifier))
		return nil, errors.New("invalid credentials")
	}

	logger.Infof("[%s] 登录成功 - Identifier: %s, OpenID: %s", p.idpType, maskIdentifier(identifier), cred.OpenID)

	return &idp.LoginResult{
		ProviderID: cred.OpenID,
		UserInfo: &idp.UserInfo{
			Nickname: cred.Nickname,
			Email:    cred.Email,
			Picture:  cred.Picture,
		},
		RawData: fmt.Sprintf(`{"identifier":"%s","type":"%s"}`, identifier, p.idpType),
	}, nil
}

// FetchAdditionalInfo 补充获取用户信息
func (*Provider) FetchAdditionalInfo(_ context.Context, infoType string, _ ...any) (*idp.AdditionalInfo, error) {
	return nil, fmt.Errorf("system provider does not support fetching %s", infoType)
}

// Prepare 准备前端所需的公开配置
func (p *Provider) Prepare() *types.ConnectionConfig {
	cfg := &types.ConnectionConfig{
		Connection: p.idpType,
	}

	if p.idpType == idp.TypeUser {
		cfg.Strategy = []string{"username", "email", "phone"}
	} else {
		cfg.Strategy = []string{"username"}
	}

	return cfg
}

// maskIdentifier 脱敏标识符（用于日志）
func maskIdentifier(identifier string) string {
	if len(identifier) <= 3 {
		return identifier + "***"
	}
	return identifier[:3] + "***"
}
