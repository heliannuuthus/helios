package token

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/json"
)

// ============= Interpreter =============

// Interpreter Token 解释器
// 负责验证和解释 token，提取身份信息
// 内部缓存 Verifier 和 decryptor 实例，避免重复构造
type Interpreter struct {
	signKeyProvider    PublicKeyProvider    // 签名公钥提供者（根据 clientID 获取）
	encryptKeyProvider SymmetricKeyProvider // 加密密钥提供者（根据 audience 获取）

	verifiers  map[string]*Verifier  // 缓存：key = audience
	decryptors map[string]*decryptor // 缓存：key = audience
	mu         sync.RWMutex
}

// NewInterpreter 创建解释器
func NewInterpreter(signKeyProvider PublicKeyProvider, encryptKeyProvider SymmetricKeyProvider) *Interpreter {
	return &Interpreter{
		signKeyProvider:    signKeyProvider,
		encryptKeyProvider: encryptKeyProvider,
		verifiers:          make(map[string]*Verifier),
		decryptors:         make(map[string]*decryptor),
	}
}

// Verifier 获取或创建绑定特定 audience 的 Verifier
func (i *Interpreter) Verifier(audience string) *Verifier {
	return getOrCreate(&i.mu, i.verifiers, audience, func() *Verifier {
		return &Verifier{
			keyProvider: i.signKeyProvider,
			audience:    audience,
		}
	})
}

// Interpret 验证并解释 token，返回 Token 接口
// 这是最完整的验证方法，会解密 footer 中的用户信息（仅 UAT）
// 返回的具体类型可通过类型断言获取：
//   - *ClientAccessToken (CAT)
//   - *UserAccessToken (UAT)
//   - *ServiceAccessToken (SAT)
//   - *ChallengeToken
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (Token, error) {
	// 1. 提取 audience
	audience, err := extractAudience(tokenString)
	if err != nil {
		return nil, err
	}

	if audience == "" {
		return nil, fmt.Errorf("%w: missing audience", ErrMissingClaims)
	}

	// 2. 验证签名并解析
	token, err := i.Verifier(audience).Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	// 3. 解密 footer 中的用户信息（仅 UAT）
	if uat, ok := token.(*UserAccessToken); ok {
		footer := extractFooter(tokenString)
		if footer != "" {
			userInfo, err := i.getDecryptor(audience).decrypt(ctx, footer)
			if err != nil {
				return nil, err
			}
			uat.SetUser(userInfo)
		}
	}

	return token, nil
}

// Verify 只验证签名，不解密 footer
// 返回的 Token 接口可通过类型断言获取具体类型
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (Token, error) {
	audience, err := extractAudience(tokenString)
	if err != nil {
		return nil, err
	}

	if audience == "" {
		return nil, fmt.Errorf("%w: missing audience", ErrMissingClaims)
	}

	return i.Verifier(audience).Verify(ctx, tokenString)
}

// getDecryptor 获取或创建绑定特定 audience 的 decryptor
func (i *Interpreter) getDecryptor(audience string) *decryptor {
	return getOrCreate(&i.mu, i.decryptors, audience, func() *decryptor {
		return &decryptor{
			keyProvider: i.encryptKeyProvider,
			audience:    audience,
		}
	})
}

// ============= Verifier =============

// Verifier 负责验证 PASETO 签名
// 绑定特定的 audience，只做验签不解密
type Verifier struct {
	keyProvider PublicKeyProvider
	audience    string
}

// Verify 验证 token 签名，返回具体的 Token 类型
func (v *Verifier) Verify(ctx context.Context, tokenString string) (Token, error) {
	// 1. 提取 clientID（先尝试 cli 字段，失败则尝试 sub）
	clientID, tokenType, err := extractClientIDAndType(tokenString)
	if err != nil {
		return nil, err
	}

	// 2. 获取公钥
	publicKey, err := v.keyProvider.Get(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("get public key for client %s: %w", clientID, err)
	}

	// 3. 验证签名
	parser := paseto.NewParser()
	parser.AddRule(paseto.NotExpired())
	parser.AddRule(paseto.ValidAt(time.Now()))

	pasetoToken, err := parser.ParseV4Public(publicKey, tokenString, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSignature, err)
	}

	// 4. 验证 audience
	audience, err := pasetoToken.GetAudience()
	if err != nil {
		return nil, fmt.Errorf("get audience: %w", err)
	}
	if audience != v.audience {
		return nil, fmt.Errorf("%w: audience mismatch, expected %s, got %s",
			ErrInvalidSignature, v.audience, audience)
	}

	// 5. 根据类型解析为具体 Token
	return parseToken(pasetoToken, tokenType)
}

// parseToken 根据类型解析 PASETO Token 为具体的 Token 类型
func parseToken(pasetoToken *paseto.Token, tokenType TokenType) (Token, error) {
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

// ============= 内部实现 =============

// decryptor 负责解密 footer
type decryptor struct {
	keyProvider SymmetricKeyProvider
	audience    string
}

func (d *decryptor) decrypt(ctx context.Context, footer string) (*UserInfo, error) {
	if footer == "" {
		return nil, nil
	}

	symmetricKey, err := d.keyProvider.Get(ctx, d.audience)
	if err != nil {
		return nil, fmt.Errorf("%w: get key for audience %s: %w", ErrUnsupportedAudience, d.audience, err)
	}

	data, err := DecryptFooter(symmetricKey, footer)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	var userInfo UserInfo
	if err := json.Unmarshal(data, &userInfo); err != nil {
		return nil, fmt.Errorf("unmarshal user info: %w", err)
	}

	return &userInfo, nil
}

// ============= 辅助函数 =============

// extractClientIDAndType 从 token 中提取 clientID 并识别类型
// CAT: 使用 sub 作为 clientID
// 其他: 使用 cli 作为 clientID
func extractClientIDAndType(tokenString string) (clientID string, tokenType TokenType, err error) {
	token, err := unsafeParseToken(tokenString)
	if err != nil {
		return "", "", err
	}

	// 检查是否有 typ 字段（ChallengeToken）
	var typ string
	if token.Get("typ", &typ) == nil && typ != "" {
		var cli string
		if token.Get("cli", &cli) != nil || cli == "" {
			return "", "", errors.New("missing cli (client_id)")
		}
		return cli, TokenTypeChallenge, nil
	}

	// 检查是否有 cli 字段
	var cli string
	if token.Get("cli", &cli) == nil && cli != "" {
		// 有 cli 字段 -> UAT 或 SAT
		// 通过 footer 区分（有 footer 是 UAT，无 footer 是 SAT）
		// 但这里只能返回默认类型，具体由 Interpret 补充
		return cli, TokenTypeUAT, nil
	}

	// 无 cli 字段 -> CAT，使用 sub 作为 clientID
	sub, err := token.GetSubject()
	if err != nil || sub == "" {
		return "", "", errors.New("missing cli and sub (client_id)")
	}
	return sub, TokenTypeCAT, nil
}

func extractAudience(tokenString string) (string, error) {
	token, err := unsafeParseToken(tokenString)
	if err != nil {
		return "", err
	}

	audience, err := token.GetAudience()
	if err != nil {
		return "", fmt.Errorf("get audience: %w", err)
	}
	return audience, nil
}

// unsafeParseToken 不验证签名解析 token（仅用于提取 claims）
func unsafeParseToken(tokenString string) (*paseto.Token, error) {
	// PASETO v4.public 格式: v4.public.{base64url_payload}.{optional_footer}
	parts := strings.Split(tokenString, ".")
	if len(parts) < 3 || parts[0] != "v4" || parts[1] != "public" {
		return nil, fmt.Errorf("%w: invalid PASETO token format", ErrInvalidSignature)
	}

	payloadBytes, err := Base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: decode payload: %w", ErrInvalidSignature, err)
	}

	// Ed25519 签名是 64 字节
	if len(payloadBytes) < 64 {
		return nil, fmt.Errorf("%w: payload too short", ErrInvalidSignature)
	}

	claimsJSON := payloadBytes[:len(payloadBytes)-64]

	var footer []byte
	if len(parts) >= 4 && parts[3] != "" {
		footer, err = Base64URLDecode(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%w: decode footer: %w", ErrInvalidSignature, err)
		}
	}

	token, err := paseto.NewTokenFromClaimsJSON(claimsJSON, footer)
	if err != nil {
		return nil, fmt.Errorf("%w: parse claims: %w", ErrInvalidSignature, err)
	}

	return token, nil
}

func extractFooter(tokenString string) string {
	// PASETO v4.public 格式: v4.public.{base64_payload}.{optional_footer}
	parts := strings.Split(tokenString, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

func getOrCreate[T any](mu *sync.RWMutex, cache map[string]*T, key string, create func() *T) *T {
	mu.RLock()
	if v, ok := cache[key]; ok {
		mu.RUnlock()
		return v
	}
	mu.RUnlock()

	mu.Lock()
	defer mu.Unlock()

	if v, ok := cache[key]; ok {
		return v
	}

	v := create()
	cache[key] = v
	return v
}
