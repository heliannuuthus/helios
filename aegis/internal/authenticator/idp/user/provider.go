// Package user provides the C-end user password login IDP.
package user

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/heliannuuthus/helios/aegis/internal/authenticator/idp"
	"github.com/heliannuuthus/helios/aegis/internal/types"
	"github.com/heliannuuthus/helios/hermes"
	"github.com/heliannuuthus/helios/hermes/models"
	"github.com/heliannuuthus/helios/pkg/logger"
)

// credential 凭证信息
type credential struct {
	OpenID       string
	PasswordHash string
	Nickname     string
	Email        string
	Picture      string
	Status       int8
}

// Provider C 端用户账号密码 Provider
type Provider struct {
	userSvc *hermes.UserService
}

// NewProvider 创建 C 端用户 Provider
func NewProvider(userSvc *hermes.UserService) *Provider {
	return &Provider{userSvc: userSvc}
}

// Type 返回 IDP 类型
func (*Provider) Type() string {
	return idp.TypeUser
}

// Login 验证账号密码
// proof: password（明文密码）
// params[0]: identifier（用户名/邮箱/手机号）
// params[1]: strategy（认证方式，当前仅支持 password）
func (p *Provider) Login(ctx context.Context, proof string, params ...any) (*models.TUserInfo, error) {
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

	logger.Infof("[user] 登录请求 - Identifier: %s", maskIdentifier(identifier))

	return p.loginByPassword(ctx, identifier, proof)
}

// loginByPassword 密码验证
func (p *Provider) loginByPassword(ctx context.Context, identifier, password string) (*models.TUserInfo, error) {
	cred, err := p.getCredential(ctx, identifier)
	if err != nil {
		logger.Warnf("[user] 用户不存在 - Identifier: %s, Error: %v", maskIdentifier(identifier), err)
		return nil, errors.New("invalid credentials")
	}

	if cred.Status != 0 {
		logger.Warnf("[user] 用户已禁用 - Identifier: %s", maskIdentifier(identifier))
		return nil, errors.New("user is disabled")
	}

	if cred.PasswordHash == "" {
		logger.Warnf("[user] 用户未设置密码 - Identifier: %s", maskIdentifier(identifier))
		return nil, errors.New("password not set, please use other login methods")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cred.PasswordHash), []byte(password)); err != nil {
		logger.Warnf("[user] 密码错误 - Identifier: %s", maskIdentifier(identifier))
		return nil, errors.New("invalid credentials")
	}

	logger.Infof("[user] 登录成功 - Identifier: %s, OpenID: %s", maskIdentifier(identifier), cred.OpenID)

	return &models.TUserInfo{
		TOpenID:  cred.OpenID,
		Nickname: cred.Nickname,
		Email:    cred.Email,
		Picture:  cred.Picture,
		RawData:  fmt.Sprintf(`{"identifier":"%s","type":"user"}`, identifier),
	}, nil
}

// getCredential 获取 C 端用户凭证
func (p *Provider) getCredential(ctx context.Context, identifier string) (*credential, error) {
	cred, err := p.userSvc.GetUserByIdentifier(ctx, identifier)
	if err != nil {
		return nil, err
	}
	return &credential{
		OpenID:       cred.OpenID,
		PasswordHash: cred.PasswordHash,
		Nickname:     cred.Nickname,
		Email:        cred.Email,
		Picture:      cred.Picture,
		Status:       cred.Status,
	}, nil
}

// Resolve 通过 principal 查找用户信息（不验证凭证）
func (p *Provider) Resolve(ctx context.Context, principal string) (*models.TUserInfo, error) {
	cred, err := p.getCredential(ctx, principal)
	if err != nil {
		return nil, err
	}
	return &models.TUserInfo{
		TOpenID:  cred.OpenID,
		Nickname: cred.Nickname,
		Email:    cred.Email,
		Picture:  cred.Picture,
	}, nil
}

// FetchAdditionalInfo 补充获取用户信息
func (*Provider) FetchAdditionalInfo(_ context.Context, infoType string, _ ...any) (*idp.AdditionalInfo, error) {
	return nil, fmt.Errorf("user provider does not support fetching %s", infoType)
}

// Prepare 准备前端所需的公开配置
// Strategy（认证方式：password, webauthn）由数据库 ApplicationIDPConfig 配置提供，
// Prepare() 只返回 Provider 自身的基础配置。
func (*Provider) Prepare() *types.ConnectionConfig {
	return &types.ConnectionConfig{
		Connection: idp.TypeUser,
	}
}

// maskIdentifier 脱敏标识符（用于日志）
func maskIdentifier(identifier string) string {
	if len(identifier) <= 3 {
		return identifier + "***"
	}
	return identifier[:3] + "***"
}
