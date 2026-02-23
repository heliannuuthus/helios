package token

import (
	"context"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
)

// ErrUnsupportedAudience audience 不支持错误
var ErrUnsupportedAudience = fmt.Errorf("unsupported audience")

// footerUserInfo footer 中存储的用户信息结构
type footerUserInfo struct {
	Subject  string `json:"sub,omitempty"`
	Nickname string `json:"nickname,omitempty"`
	Picture  string `json:"picture,omitempty"`
	Email    string `json:"email,omitempty"`
	Phone    string `json:"phone,omitempty"`
}

// Interpreter Token 解释器
type Interpreter struct {
	signKeyStore    *key.Store
	encryptKeyStore *key.Store

	verifiers  map[string]*Verifier
	decryptors map[string]*Decryptor
	mu         sync.RWMutex
}

// NewInterpreter 创建解释器
func NewInterpreter(signKeyStore *key.Store, encryptKeyStore *key.Store) *Interpreter {
	return &Interpreter{
		signKeyStore:    signKeyStore,
		encryptKeyStore: encryptKeyStore,
		verifiers:       make(map[string]*Verifier),
		decryptors:      make(map[string]*Decryptor),
	}
}

// Interpret 验证并解释 token，返回 Token 接口
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (Token, error) {
	pasetoToken, err := UnsafeParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := GetClientID(pasetoToken)
	if err != nil {
		return nil, err
	}

	audience, err := GetAudience(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMissingClaims, err)
	}

	tokenType := DetectType(pasetoToken)

	verifier := i.getVerifier(clientID)

	t, err := verifier.Verify(ctx, tokenString, tokenType)
	if err != nil {
		return nil, err
	}

	if uat, ok := t.(*UserAccessToken); ok {
		footer := ExtractFooter(tokenString)
		if footer != "" {
			userInfo, err := i.decryptFooter(ctx, footer, audience)
			if err != nil {
				return nil, err
			}
			if userInfo != nil {
				uat.SetUserInfo(userInfo.Subject, userInfo.Nickname, userInfo.Picture, userInfo.Email, userInfo.Phone)
			}
		}
	}

	return t, nil
}

// Verify 只验证签名，不解密 footer
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (Token, error) {
	pasetoToken, err := UnsafeParse(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := GetClientID(pasetoToken)
	if err != nil {
		return nil, err
	}

	tokenType := DetectType(pasetoToken)

	verifier := i.getVerifier(clientID)

	return verifier.Verify(ctx, tokenString, tokenType)
}

func (i *Interpreter) getVerifier(clientID string) *Verifier {
	i.mu.RLock()
	v, ok := i.verifiers[clientID]
	i.mu.RUnlock()

	if ok {
		return v
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// double check
	if v, ok := i.verifiers[clientID]; ok {
		return v
	}

	v = NewVerifier(i.signKeyStore, clientID)
	i.verifiers[clientID] = v
	return v
}

func (i *Interpreter) getDecryptor(audience string) *Decryptor {
	i.mu.RLock()
	d, ok := i.decryptors[audience]
	i.mu.RUnlock()

	if ok {
		return d
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	// double check
	if d, ok := i.decryptors[audience]; ok {
		return d
	}

	d = NewDecryptor(i.encryptKeyStore, audience)
	i.decryptors[audience] = d
	return d
}

func (i *Interpreter) decryptFooter(ctx context.Context, footer string, audience string) (*footerUserInfo, error) {
	if footer == "" {
		return nil, nil
	}

	decryptor := i.getDecryptor(audience)

	var userInfo footerUserInfo
	if err := decryptor.Decrypt(ctx, footer, &userInfo); err != nil {
		return nil, fmt.Errorf("decrypt footer: %w", err)
	}

	return &userInfo, nil
}
