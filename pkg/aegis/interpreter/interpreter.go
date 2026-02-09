// Package interpreter 提供 PASETO Token 的验证和解释功能
package interpreter

import (
	"context"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/keys"
	"github.com/heliannuuthus/helios/pkg/aegis/pasetokit"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	"github.com/heliannuuthus/helios/pkg/json"
)

// 错误定义
var ErrUnsupportedAudience = fmt.Errorf("unsupported audience")

// footerUserInfo footer 中存储的用户信息结构（用于 JSON 反序列化）
type footerUserInfo struct {
	Subject     string `json:"sub,omitempty"`
	InternalUID string `json:"uid,omitempty"`
	Nickname    string `json:"nickname,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
}

// Interpreter Token 解释器
// 负责验证和解释 token，提取身份信息
// 内部缓存 Verifier 和 decryptor 实例，避免重复构造
type Interpreter struct {
	signKeyProvider    keys.PublicKeyProvider    // 签名公钥提供者（根据 clientID 获取）
	encryptKeyProvider keys.SymmetricKeyProvider // 加密密钥提供者（根据 audience 获取）

	verifiers  map[string]*token.Verifier // 缓存：key = client_id
	decryptors map[string]*decryptor      // 缓存：key = audience
	mu         sync.RWMutex
}

// NewInterpreter 创建解释器
func NewInterpreter(signKeyProvider keys.PublicKeyProvider, encryptKeyProvider keys.SymmetricKeyProvider) *Interpreter {
	return &Interpreter{
		signKeyProvider:    signKeyProvider,
		encryptKeyProvider: encryptKeyProvider,
		verifiers:          make(map[string]*token.Verifier),
		decryptors:         make(map[string]*decryptor),
	}
}

// getVerifier 获取或创建绑定特定 client_id 的 Verifier
func (i *Interpreter) getVerifier(clientID string) *token.Verifier {
	return getOrCreate(&i.mu, i.verifiers, clientID, func() *token.Verifier {
		return token.NewVerifier(i.signKeyProvider, clientID)
	})
}

// Interpret 验证并解释 token，返回 Token 接口
// 这是最完整的验证方法，会解密 footer 中的用户信息（仅 UAT）
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (token.Token, error) {
	// 1. 提取 token 信息
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, err
	}

	if info.Audience == "" {
		return nil, fmt.Errorf("%w: missing audience", token.ErrMissingClaims)
	}

	// 2. 获取 Verifier（按 client_id 缓存）
	verifier := i.getVerifier(info.ClientID)

	// 3. 验证签名
	t, err := verifier.Verify(ctx, tokenString, info)
	if err != nil {
		return nil, err
	}

	// 4. 解密 footer 中的用户信息（仅 UAT）
	if uat, ok := token.AsUAT(t); ok {
		footer := token.ExtractFooter(tokenString)
		if footer != "" {
			userInfo, err := i.getDecryptor(info.Audience).decrypt(ctx, footer)
			if err != nil {
				return nil, err
			}
			if userInfo != nil {
				uat.SetUserInfo(userInfo.Subject, userInfo.InternalUID, userInfo.Nickname, userInfo.Picture, userInfo.Email, userInfo.Phone)
			}
		}
	}

	return t, nil
}

// Verify 只验证签名，不解密 footer
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (token.Token, error) {
	info, err := token.Extract(tokenString)
	if err != nil {
		return nil, err
	}

	if info.Audience == "" {
		return nil, fmt.Errorf("%w: missing audience", token.ErrMissingClaims)
	}

	return i.getVerifier(info.ClientID).Verify(ctx, tokenString, info)
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

// ==================== decryptor ====================

type decryptor struct {
	keyProvider keys.SymmetricKeyProvider
	audience    string
}

func (d *decryptor) decrypt(ctx context.Context, footer string) (*footerUserInfo, error) {
	if footer == "" {
		return nil, nil
	}

	symmetricKey, err := d.keyProvider.Get(ctx, d.audience)
	if err != nil {
		return nil, fmt.Errorf("%w: get key for audience %s: %w", ErrUnsupportedAudience, d.audience, err)
	}

	data, err := pasetokit.DecryptFooter(symmetricKey, footer)
	if err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	var userInfo footerUserInfo
	if err := json.Unmarshal(data, &userInfo); err != nil {
		return nil, fmt.Errorf("unmarshal user info: %w", err)
	}

	return &userInfo, nil
}

// ==================== 辅助函数 ====================

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
