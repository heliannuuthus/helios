package token

import (
	"context"
	"errors"
	"fmt"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/config"
	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/aegis/pasetokit"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/json"
)

// Service Token 服务
// 负责签发 UAT/SAT/ChallengeToken、验证 CAT/ChallengeToken
type Service struct {
	issuerName string
	cache      *cache.Manager
}

// NewService 创建 Token 服务
func NewService(cacheManager *cache.Manager) *Service {
	return &Service{
		issuerName: config.GetAegisIssuer(),
		cache:      cacheManager,
	}
}

// GetIssuerName 返回签发者名称
func (s *Service) GetIssuerName() string {
	return s.issuerName
}

// ============= 签发 =============

// Issue 签发 token（统一入口）
// 根据 Token.Type() 自动路由到对应的签发逻辑
func (s *Service) Issue(ctx context.Context, t token.Token) (string, error) {
	switch t.Type() {
	case token.TokenTypeUAT:
		uat, ok := t.(*token.UserAccessToken)
		if !ok {
			return "", fmt.Errorf("%w: expected UserAccessToken", token.ErrUnsupportedToken)
		}
		return s.issueUserToken(ctx, uat)

	case token.TokenTypeSAT:
		sat, ok := t.(*token.ServiceAccessToken)
		if !ok {
			return "", fmt.Errorf("%w: expected ServiceAccessToken", token.ErrUnsupportedToken)
		}
		return s.issueServiceToken(ctx, sat)

	case token.TokenTypeChallenge:
		ct, ok := t.(*token.ChallengeToken)
		if !ok {
			return "", fmt.Errorf("%w: expected ChallengeToken", token.ErrUnsupportedToken)
		}
		return s.issueChallengeToken(ctx, ct)

	case token.TokenTypeCAT:
		return "", fmt.Errorf("%w: CAT should be issued by client using pkg/aegis/token.Issuer", token.ErrUnsupportedToken)

	default:
		return "", fmt.Errorf("%w: %s", token.ErrUnsupportedToken, t.Type())
	}
}

// issueUserToken 签发用户访问令牌
func (s *Service) issueUserToken(ctx context.Context, uat *token.UserAccessToken) (string, error) {
	if !uat.HasUser() {
		return "", errors.New("user claims required for UserAccessToken")
	}

	footer, err := s.encryptFooter(ctx, uat)
	if err != nil {
		return "", fmt.Errorf("encrypt footer: %w", err)
	}

	pasetoToken, err := token.Build(uat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return s.sign(ctx, pasetoToken, uat.GetClientID(), footer)
}

// issueServiceToken 签发服务访问令牌
func (s *Service) issueServiceToken(ctx context.Context, sat *token.ServiceAccessToken) (string, error) {
	pasetoToken, err := token.Build(sat)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return s.sign(ctx, pasetoToken, sat.GetClientID(), nil)
}

// issueChallengeToken 签发 Challenge 验证令牌
func (s *Service) issueChallengeToken(ctx context.Context, ct *token.ChallengeToken) (string, error) {
	pasetoToken, err := token.Build(ct)
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	return s.sign(ctx, pasetoToken, ct.GetClientID(), nil)
}

// ============= 验证 =============

// VerifyUAT 验证 UserAccessToken（只验签不解密）
func (s *Service) VerifyUAT(ctx context.Context, tokenString string) (*token.UserAccessToken, error) {
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract token info: %w", err)
	}

	publicKey, err := s.getPublicKey(ctx, info.ClientID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	pasetoToken, err := token.VerifySignature(publicKey, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	return token.ParseUserAccessToken(pasetoToken)
}

// InterpretUAT 验证并解密 UserAccessToken
func (s *Service) InterpretUAT(ctx context.Context, tokenString string) (*token.UserAccessToken, error) {
	uat, err := s.VerifyUAT(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	footer := token.ExtractFooter(tokenString)
	if footer == "" {
		return uat, nil
	}

	svc, err := s.cache.GetService(ctx, uat.GetAudience())
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	// 从服务密钥（32 字节 seed）派生对称加密密钥
	symmetricKey, err := keys.DeriveSymmetricKey(svc.Key)
	if err != nil {
		return nil, fmt.Errorf("derive symmetric key: %w", err)
	}

	decrypted, err := pasetokit.DecryptFooter(symmetricKey, footer)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	// 解析 footer 中的用户信息
	var footerData struct {
		Subject     string `json:"sub,omitempty"`
		InternalUID string `json:"uid,omitempty"`
		Nickname    string `json:"nickname,omitempty"`
		Picture     string `json:"picture,omitempty"`
		Email       string `json:"email,omitempty"`
		Phone       string `json:"phone,omitempty"`
	}
	if err := json.Unmarshal(decrypted, &footerData); err != nil {
		return nil, fmt.Errorf("unmarshal user info: %w", err)
	}

	uat.SetUserInfo(footerData.Subject, footerData.InternalUID, footerData.Nickname, footerData.Picture, footerData.Email, footerData.Phone)
	return uat, nil
}

// VerifyChallengeToken 验证 ChallengeToken
func (s *Service) VerifyChallengeToken(ctx context.Context, tokenString string) (*token.ChallengeToken, error) {
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract token info: %w", err)
	}

	publicKey, err := s.getPublicKey(ctx, info.ClientID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	pasetoToken, err := token.VerifySignature(publicKey, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	return token.ParseChallengeToken(pasetoToken)
}

// VerifyCAT 验证 ClientAccessToken
// CAT 由应用使用其 Ed25519 密钥签发，用于 Client-Credentials 流程
func (s *Service) VerifyCAT(ctx context.Context, tokenString string) (*token.ClientAccessToken, error) {
	// 1. 提取 token 信息（CAT 使用 sub 作为 clientID）
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract token info: %w", err)
	}

	// 2. 获取应用公钥
	app, err := s.cache.GetApplication(ctx, info.ClientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	if len(app.Key) == 0 {
		return nil, errors.New("application has no key")
	}

	// 从应用密钥（32 字节 seed）派生公钥
	publicKey, err := keys.DerivePublicKey(app.Key)
	if err != nil {
		return nil, fmt.Errorf("derive app public key: %w", err)
	}

	// 3. 验证签名
	pasetoToken, err := token.VerifySignature(publicKey, tokenString)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 4. 解析为 ClientAccessToken
	cat, err := token.ParseClientAccessToken(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse client access token: %w", err)
	}
	return cat, nil
}

// ============= 内部方法 =============

// sign 签名 PASETO Token
func (s *Service) sign(ctx context.Context, pasetoToken *paseto.Token, clientID string, footer []byte) (string, error) {
	// 1. 获取应用信息
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return "", fmt.Errorf("get application: %w", err)
	}

	// 2. 获取域签名密钥
	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return "", fmt.Errorf("get domain: %w", err)
	}

	// 3. 从域密钥（32 字节 Ed25519 seed）直接解析签名密钥
	secretKey, err := keys.ParseSecretKeyFromSeed(domain.Main)
	if err != nil {
		return "", fmt.Errorf("parse sign key from seed: %w", err)
	}

	// 4. 签名
	return pasetoToken.V4Sign(secretKey, footer), nil
}

// encryptFooter 加密用户信息到 footer
func (s *Service) encryptFooter(ctx context.Context, uat *token.UserAccessToken) ([]byte, error) {
	svc, err := s.cache.GetService(ctx, uat.GetAudience())
	if err != nil {
		return nil, fmt.Errorf("get service key: %w", err)
	}

	data, err := json.Marshal(uat.GetUserForFooter())
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}

	// 从服务密钥（32 字节 seed）派生对称加密密钥
	symmetricKey, err := keys.DeriveSymmetricKey(svc.Key)
	if err != nil {
		return nil, fmt.Errorf("derive symmetric key: %w", err)
	}

	return []byte(pasetokit.EncryptFooter(symmetricKey, data)), nil
}

// getPublicKey 获取域的公钥
func (s *Service) getPublicKey(ctx context.Context, clientID string) (paseto.V4AsymmetricPublicKey, error) {
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("get application: %w", err)
	}

	domain, err := s.cache.GetDomain(ctx, app.DomainID)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("get domain: %w", err)
	}

	publicKey, err := keys.ParsePublicKeyFromSeed(domain.Main)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("parse public key from seed: %w", err)
	}

	return publicKey, nil
}
