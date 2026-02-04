package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/internal/aegis/cache"
	"github.com/heliannuuthus/helios/internal/config"
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

// Issue 签发 token
func (s *Service) Issue(ctx context.Context, accessToken token.AccessToken) (string, error) {
	switch t := accessToken.(type) {
	case *UserAccessToken:
		return s.issueUserToken(ctx, t)
	case *ServiceAccessToken:
		return s.issueServiceToken(ctx, t)
	case *ChallengeToken:
		return s.issueChallengeToken(ctx, t)
	default:
		return "", errors.New("unsupported token type")
	}
}

// issueUserToken 签发用户访问令牌
func (s *Service) issueUserToken(ctx context.Context, uat *UserAccessToken) (string, error) {
	// 1. 验证用户信息
	if uat.GetUser() == nil {
		return "", errors.New("user claims required for UserAccessToken")
	}

	// 2. 加密用户信息到 footer
	footer, err := s.encryptFooter(ctx, uat)
	if err != nil {
		return "", fmt.Errorf("encrypt footer: %w", err)
	}

	// 3. 构建 PASETO Token
	pasetoToken, err := uat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 4. 签名（带 footer）
	signed, err := s.sign(ctx, pasetoToken, uat.GetClientID(), footer)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

// issueServiceToken 签发服务访问令牌
func (s *Service) issueServiceToken(ctx context.Context, sat *ServiceAccessToken) (string, error) {
	// 1. 构建 PASETO Token
	pasetoToken, err := sat.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 2. 签名（无 footer）
	signed, err := s.sign(ctx, pasetoToken, sat.GetClientID(), nil)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

// issueChallengeToken 签发 Challenge 验证令牌
func (s *Service) issueChallengeToken(ctx context.Context, ct *ChallengeToken) (string, error) {
	// 1. 构建 PASETO Token
	pasetoToken, err := ct.Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	// 2. 签名（无 footer，ChallengeToken 不需要加密用户信息）
	signed, err := s.sign(ctx, pasetoToken, ct.GetClientID(), nil)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}

	return signed, nil
}

// ============= 验证 =============

// VerifyUAT 验证 UserAccessToken（只验签不解密）
// 返回 token 中的基本信息，不包含解密后的用户信息
func (s *Service) VerifyUAT(ctx context.Context, tokenString string) (*UserAccessToken, error) {
	// 1. 提取 clientID（先不验证签名解析）
	clientID, err := extractClientID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract client_id: %w", err)
	}

	// 2. 获取公钥
	publicKey, err := s.getPublicKey(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// 3. 验证签名
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 4. 解析为 UserAccessToken
	uat, err := parseUserAccessToken(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse user access token: %w", err)
	}
	return uat, nil
}

// InterpretUAT 验证并解密 UserAccessToken
// 返回完整的用户信息（包含解密后的用户 Claims）
func (s *Service) InterpretUAT(ctx context.Context, tokenString string) (*UserAccessToken, error) {
	// 1. 提取 clientID
	clientID, err := extractClientID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract client_id: %w", err)
	}

	// 2. 获取公钥
	publicKey, err := s.getPublicKey(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// 3. 验证签名
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 4. 解析为 UserAccessToken
	uat, err := parseUserAccessToken(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse user access token: %w", err)
	}

	// 5. 提取并解密 footer
	footer := extractFooter(tokenString)
	if footer == "" {
		return uat, nil
	}

	svc, err := s.cache.GetService(ctx, uat.GetAudience())
	if err != nil {
		return nil, fmt.Errorf("get service: %w", err)
	}

	symmetricKey, err := token.ParseSymmetricKeyFromBytes(svc.Key)
	if err != nil {
		return nil, fmt.Errorf("parse symmetric key: %w", err)
	}

	decrypted, err := token.DecryptFooter(symmetricKey, footer)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	// 6. 解析用户信息并设置到 UAT
	var userInfo token.UserInfo
	if err := json.Unmarshal(decrypted, &userInfo); err != nil {
		return nil, fmt.Errorf("unmarshal user info: %w", err)
	}

	uat.SetUser(&userInfo)
	return uat, nil
}

// VerifyChallengeToken 验证 ChallengeToken
// ChallengeToken 由 Auth Service 签发，用于证明某个 principal 已完成挑战
func (s *Service) VerifyChallengeToken(ctx context.Context, tokenString string) (*ChallengeToken, error) {
	// 1. 提取 clientID
	clientID, err := extractClientID(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract client_id: %w", err)
	}

	// 2. 获取公钥
	publicKey, err := s.getPublicKey(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get public key: %w", err)
	}

	// 3. 验证签名
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// 4. 解析为 ChallengeToken
	ct, err := parseChallengeToken(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("parse challenge token: %w", err)
	}
	return ct, nil
}

// VerifyCAT 验证 ClientAccessToken
// CAT 由应用使用其 Ed25519 密钥签发，用于 Client-Credentials 流程
func (s *Service) VerifyCAT(ctx context.Context, tokenString string) (*token.ClientAccessToken, error) {
	// 1. 提取 subject（即 clientID）
	clientID, err := extractSubject(tokenString)
	if err != nil {
		return nil, fmt.Errorf("extract subject: %w", err)
	}

	// 2. 获取应用公钥
	app, err := s.cache.GetApplication(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get application: %w", err)
	}

	if len(app.Key) == 0 {
		return nil, errors.New("application has no key")
	}

	publicKey, err := token.ParsePublicKeyFromJWK(app.Key)
	if err != nil {
		return nil, fmt.Errorf("parse app public key: %w", err)
	}

	// 3. 验证签名
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(publicKey, tokenString, nil)
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

	// 3. 解析签名密钥
	secretKey, err := token.ParseSecretKeyFromJWK(domain.SignKey)
	if err != nil {
		return "", fmt.Errorf("parse sign key: %w", err)
	}

	// 4. 签名
	return pasetoToken.V4Sign(secretKey, footer), nil
}

// encryptFooter 加密用户信息到 footer
func (s *Service) encryptFooter(ctx context.Context, uat *UserAccessToken) ([]byte, error) {
	// 1. 获取服务加密密钥
	svc, err := s.cache.GetService(ctx, uat.GetAudience())
	if err != nil {
		return nil, fmt.Errorf("get service key: %w", err)
	}

	// 2. 序列化 claims
	data, err := json.Marshal(uat.GetUser())
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}

	// 3. 解析对称密钥
	symmetricKey, err := token.ParseSymmetricKeyFromBytes(svc.Key)
	if err != nil {
		return nil, fmt.Errorf("parse symmetric key: %w", err)
	}

	// 4. 加密
	encrypted := token.EncryptFooter(symmetricKey, data)
	return []byte(encrypted), nil
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

	secretKey, err := token.ParseSecretKeyFromJWK(domain.SignKey)
	if err != nil {
		return paseto.V4AsymmetricPublicKey{}, fmt.Errorf("parse sign key: %w", err)
	}

	return secretKey.Public(), nil
}

// extractClientID 从 token 中提取 cli 字段（不验证签名）
func extractClientID(tokenString string) (string, error) {
	pasetoToken, err := unsafeParseToken(tokenString)
	if err != nil {
		return "", err
	}

	var clientID string
	if err := pasetoToken.Get("cli", &clientID); err != nil || clientID == "" {
		return "", errors.New("missing cli (client_id)")
	}

	return clientID, nil
}

// extractSubject 从 token 中提取 sub 字段（不验证签名）
func extractSubject(tokenString string) (string, error) {
	pasetoToken, err := unsafeParseToken(tokenString)
	if err != nil {
		return "", err
	}

	subject, err := pasetoToken.GetSubject()
	if err != nil || subject == "" {
		return "", errors.New("missing sub (client_id)")
	}

	return subject, nil
}

// unsafeParseToken 不验证签名解析 token（仅用于提取 claims）
func unsafeParseToken(tokenString string) (*paseto.Token, error) {
	// PASETO v4.public 格式: v4.public.{base64url_payload}.{optional_footer}
	parts := strings.Split(tokenString, ".")
	if len(parts) < 3 || parts[0] != "v4" || parts[1] != "public" {
		return nil, errors.New("invalid PASETO token format")
	}

	// 从 base64url 解码 payload
	payloadBytes, err := token.Base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	// Ed25519 签名是 64 字节
	if len(payloadBytes) < 64 {
		return nil, errors.New("payload too short")
	}

	claimsJSON := payloadBytes[:len(payloadBytes)-64]

	var footer []byte
	if len(parts) >= 4 && parts[3] != "" {
		footer, err = token.Base64URLDecode(parts[3])
		if err != nil {
			return nil, fmt.Errorf("decode footer: %w", err)
		}
	}

	pasetoToken, err := paseto.NewTokenFromClaimsJSON(claimsJSON, footer)
	if err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	return pasetoToken, nil
}

// extractFooter 从 token 中提取 footer
func extractFooter(tokenString string) string {
	// PASETO v4.public 格式: v4.public.{base64_payload}.{optional_footer}
	parts := strings.Split(tokenString, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}
