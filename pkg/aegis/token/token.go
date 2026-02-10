// Package token 定义 PASETO Token 类型和接口
package token

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/pasetokit"
)

// 错误定义
var (
	ErrMissingClaims    = errors.New("missing required claims")
	ErrUnsupportedToken = errors.New("unsupported token type")
)

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

// ==================== TokenInfo ====================

// TokenInfo 从 token 中提取的基本信息（不验证签名）
type TokenInfo struct {
	ClientID  string    // 客户端 ID
	Audience  string    // 目标受众
	TokenType TokenType // Token 类型
}

// Extract 从 token 字符串中提取基本信息（不验证签名）
// 用于在验证前获取 client_id 和 audience
func Extract(tokenString string) (*TokenInfo, error) {
	clientID, tokenType, err := extractClientIDAndType(tokenString)
	if err != nil {
		return nil, err
	}

	audience, err := extractAudience(tokenString)
	if err != nil {
		return nil, err
	}

	return &TokenInfo{
		ClientID:  clientID,
		Audience:  audience,
		TokenType: tokenType,
	}, nil
}

// ==================== 类型断言辅助函数 ====================

// AsCAT 将 Token 断言为 ClientAccessToken
func AsCAT(t Token) (*ClientAccessToken, bool) {
	cat, ok := t.(*ClientAccessToken)
	return cat, ok
}

// AsUAT 将 Token 断言为 UserAccessToken
func AsUAT(t Token) (*UserAccessToken, bool) {
	uat, ok := t.(*UserAccessToken)
	return uat, ok
}

// AsSAT 将 Token 断言为 ServiceAccessToken
func AsSAT(t Token) (*ServiceAccessToken, bool) {
	sat, ok := t.(*ServiceAccessToken)
	return sat, ok
}

// AsChallenge 将 Token 断言为 ChallengeToken
func AsChallenge(t Token) (*ChallengeToken, bool) {
	ct, ok := t.(*ChallengeToken)
	return ct, ok
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

// extractClientIDAndType 从 token 中提取 clientID 并识别类型
func extractClientIDAndType(tokenString string) (clientID string, tokenType TokenType, err error) {
	token, err := UnsafeParseToken(tokenString)
	if err != nil {
		return "", "", err
	}

	// 检查是否有 typ 字段（ChallengeToken）
	var typ string
	if token.Get(ClaimType, &typ) == nil && typ != "" {
		var cli string
		if token.Get(ClaimCli, &cli) != nil || cli == "" {
			return "", "", errors.New("missing cli (client_id)")
		}
		return cli, TokenTypeChallenge, nil
	}

	// 检查是否有 cli 字段
	var cli string
	if token.Get(ClaimCli, &cli) == nil && cli != "" {
		return cli, TokenTypeUAT, nil
	}

	// 无 cli 字段 -> CAT，使用 sub 作为 clientID
	sub, err := token.GetSubject()
	if err != nil || sub == "" {
		return "", "", errors.New("missing cli and sub (client_id)")
	}
	return sub, TokenTypeCAT, nil
}

// extractAudience 从 token 中提取 audience
func extractAudience(tokenString string) (string, error) {
	token, err := UnsafeParseToken(tokenString)
	if err != nil {
		return "", err
	}

	audience, err := token.GetAudience()
	if err != nil {
		return "", fmt.Errorf("get audience: %w", err)
	}
	return audience, nil
}

// UnsafeParseToken 不验证签名解析 token（仅用于提取 claims）
// 安全警告：此方法跳过签名验证，返回的数据不可信，仅用于在验证前提取 clientID/audience 以查找对应密钥
// PASETO v4.public 使用 Ed25519，签名固定 64 字节
func UnsafeParseToken(tokenString string) (*paseto.Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) < 3 || parts[0] != PasetoVersion || parts[1] != PasetoPurpose {
		return nil, fmt.Errorf("%w: invalid PASETO token format", pasetokit.ErrInvalidSignature)
	}

	payloadBytes, err := pasetokit.Base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", pasetokit.ErrInvalidSignature, err)
	}

	if len(payloadBytes) < 64 {
		return nil, fmt.Errorf("%w: payload too short", pasetokit.ErrInvalidSignature)
	}

	claimsJSON := payloadBytes[:len(payloadBytes)-64]

	var footer []byte
	if len(parts) >= 4 && parts[3] != "" {
		footer, err = pasetokit.Base64URLDecode(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: decode footer: %w", pasetokit.ErrInvalidSignature, err)
		}
	}

	token, err := paseto.NewTokenFromClaimsJSON(claimsJSON, footer)
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", pasetokit.ErrInvalidSignature, err)
	}

	return token, nil
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
