// Package token 定义 PASETO Token 类型和接口
package token

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"
)

// 错误定义
var (
	ErrMissingClaims    = errors.New("missing required claims")
	ErrUnsupportedToken = errors.New("unsupported token type")
	ErrInvalidSignature = errors.New("invalid signature")
)

// ==================== Footer 加密解密 ====================

// Encrypt 使用对称密钥加密纯文本（用于 footer）
func Encrypt(key paseto.V4SymmetricKey, plaintext string) string {
	t := paseto.NewToken()
	t.Set("d", plaintext)
	return t.V4Encrypt(key, nil)
}

// Decrypt 使用对称密钥解密 PASETO local token
func Decrypt(key paseto.V4SymmetricKey, encrypted string) (string, error) {
	parser := paseto.NewParser()
	t, err := parser.ParseV4Local(key, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	plaintext, err := t.GetString("d")
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// ==================== Token 签名 ====================

// SignToken 签名 Token
func SignToken(t *paseto.Token, secretKey paseto.V4AsymmetricSecretKey, footer []byte) string {
	var footerPtr []byte
	if len(footer) > 0 {
		footerPtr = footer
	}
	return t.V4Sign(secretKey, footerPtr)
}

// ==================== Base64 工具函数 ====================

// base64URLDecode Base64URL 解码（无填充）
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ==================== Token 接口 ====================

// Token 所有凭证的统一只读接口
// 用于解析后返回，业务方通过类型断言获取具体类型
type Token interface {
	// Type 返回凭证类型标识
	Type() TokenType

	// 基础 Claims Getter 方法
	GetIssuer() string
	GetClientID() string
	GetAudience() string
	GetSubject() string
	GetIssuedAt() time.Time
	GetExpiresAt() time.Time
	GetJTI() string

	// IsExpired 检查是否已过期
	IsExpired() bool
}

// tokenBuilder 内部签发接口
type tokenBuilder interface {
	Token
	build() (*paseto.Token, error)
}

// Build 构建 PASETO Token（供签发使用）
// 传入的 Token 必须是可签发的具体类型（UAT/SAT/CAT/ChallengeToken）
func Build(t Token) (*paseto.Token, error) {
	if builder, ok := t.(tokenBuilder); ok {
		return builder.build()
	}
	return nil, fmt.Errorf("%w: token does not support building", ErrUnsupportedToken)
}

// ==================== TokenType ====================

// TokenType 凭证类型
type TokenType string

const (
	TokenTypeCAT       TokenType = "cat"       // Client Access Token - 客户端自签发
	TokenTypeUAT       TokenType = "uat"       // User Access Token - 用户访问令牌
	TokenTypeSAT       TokenType = "sat"       // Service Access Token - M2M 服务令牌
	TokenTypeChallenge TokenType = "challenge" // Challenge Token - 验证挑战令牌
)

// DetectType 根据 claims 推断 token 类型
// 规则：有 ctp 字段 -> Challenge，有 cli 字段 -> UAT，否则 -> CAT
func DetectType(t *paseto.Token) TokenType {
	var ctp string
	if t.Get(ClaimChannelType, &ctp) == nil && ctp != "" {
		return TokenTypeChallenge
	}

	var cli string
	if t.Get(ClaimCli, &cli) == nil && cli != "" {
		return TokenTypeUAT
	}

	return TokenTypeCAT
}

// GetClientID 从 paseto.Token 中提取 clientID
// UAT/Challenge 使用 cli 字段，CAT 使用 sub 字段
func GetClientID(t *paseto.Token) (string, error) {
	var cli string
	if t.Get(ClaimCli, &cli) == nil && cli != "" {
		return cli, nil
	}

	sub, err := t.GetSubject()
	if err != nil || sub == "" {
		return "", errors.New("missing cli and sub (client_id)")
	}
	return sub, nil
}

// GetAudience 从 paseto.Token 中提取 audience
func GetAudience(t *paseto.Token) (string, error) {
	return t.GetAudience()
}


// ==================== Token 解析 ====================

// ParseToken 根据类型解析 PASETO Token 为具体的 Token 类型
func ParseToken(pasetoToken *paseto.Token, tokenType TokenType) (Token, error) {
	switch tokenType {
	case TokenTypeCAT:
		return ParseClientAccessToken(pasetoToken)
	case TokenTypeUAT:
		return ParseUserAccessToken(pasetoToken)
	case TokenTypeSAT:
		return ParseServiceAccessToken(pasetoToken)
	case TokenTypeChallenge:
		return ParseChallengeToken(pasetoToken)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedToken, tokenType)
	}
}

// ==================== 解析辅助函数 ====================

// UnsafeParse 从 token 字符串中解析 claims（不验证签名）
// 安全警告：返回的数据不可信，仅用于在验证前提取 clientID/audience 以查找对应密钥
var UnsafeParse = UnsafeParseToken

// UnsafeParseToken 不验证签名解析 token（仅用于提取 claims）
// 安全警告：此方法跳过签名验证，返回的数据不可信，仅用于在验证前提取 clientID/audience 以查找对应密钥
// PASETO v4.public 使用 Ed25519，签名固定 64 字节
func UnsafeParseToken(tokenString string) (*paseto.Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 3 || parts[0] != PasetoVersion || parts[1] != PasetoPurpose {
		return nil, fmt.Errorf("%w: invalid PASETO token format", ErrInvalidSignature)
	}

	payloadBytes, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", ErrInvalidSignature, err)
	}

	if len(payloadBytes) < 64 {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidSignature)
	}

	claimsJSON := payloadBytes[:len(payloadBytes)-64]

	var footer []byte
	if len(parts) >= 4 && parts[3] != "" {
		footer, err = base64URLDecode(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: decode footer: %w", ErrInvalidSignature, err)
		}
	}

	t, err := paseto.NewTokenFromClaimsJSON(claimsJSON, footer)
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrInvalidSignature, err)
	}

	return t, nil
}

// ExtractFooter 从 token 字符串中提取 footer
func ExtractFooter(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

// ==================== Scope 辅助函数 ====================

// HasScope 检查 scope 字符串是否包含某个 scope
func HasScope(scopeStr, scope string) bool {
	for _, s := range strings.Fields(scopeStr) {
		if s == scope {
			return true
		}
	}
	return false
}

// parseScopeSet 解析 scope 字符串为集合
func parseScopeSet(scope string) map[string]bool {
	set := make(map[string]bool)
	for _, s := range strings.Fields(scope) {
		set[s] = true
	}
	return set
}
