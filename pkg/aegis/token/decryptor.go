package token

import (
	"context"
	"fmt"
	"sync"

	"aidanwoods.dev/go-paseto"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	pasetokit "github.com/heliannuuthus/helios/pkg/aegis/utils/paseto"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
	"github.com/heliannuuthus/helios/pkg/logger"
)

var ErrDecryptFailed = pasetokit.ErrDecryptFailed

// Decryptor 解密 v4.local token，持有 Extractor 引用并管理 per-clientID 的 Verifier。
// 解密密钥的管理完全独立于 Extractor。
type Decryptor struct {
	extractor *extractor

	provider key.Provider

	mu        sync.RWMutex
	keys      map[string]paseto.V4SymmetricKey
	verifiers map[string]*Verifier
}

func NewDecryptor(audience string, encryptKeyProvider key.Provider, publicKeyProvider key.Provider) *Decryptor {
	d := &Decryptor{
		extractor: NewExtractor(audience, publicKeyProvider),
		provider:  encryptKeyProvider,
		keys:      make(map[string]paseto.V4SymmetricKey),
		verifiers: make(map[string]*Verifier),
	}

	if encryptKeyProvider != nil {
		if sub, ok := encryptKeyProvider.(key.Subscribable); ok {
			sub.Subscribe(d.extractor.audience, func(newKeys [][]byte) {
				if err := d.rebuild(newKeys); err != nil {
					logger.Warnf("[Decryptor] rebuild keys failed for %s: %v", d.extractor.audience, err)
				}
			})
		}
	}

	return d
}

// Verifier 按 clientID 获取或创建 Verifier。
func (d *Decryptor) Verifier(clientID string) *Verifier {
	d.mu.RLock()
	v, ok := d.verifiers[clientID]
	d.mu.RUnlock()
	if ok {
		return v
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := d.verifiers[clientID]; ok {
		return v
	}

	v = newVerifier(d.extractor, clientID)
	d.verifiers[clientID] = v
	return v
}

// Interpret 完整的 token 解析：UnsafeParse 提取 clientID -> 验签 -> 类型检测 -> ParseToken -> UAT sub 解密。
func (d *Decryptor) Interpret(ctx context.Context, tokenString string) (tokendef.Token, error) {
	pasetoToken, err := tokendef.UnsafeParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := tokendef.GetClientID(pasetoToken)
	if err != nil {
		return nil, err
	}

	pasetoToken, err = d.Verifier(clientID).Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	t, err := tokendef.ParseToken(pasetoToken, tokendef.DetectType(pasetoToken))
	if err != nil {
		return nil, err
	}

	if uat, ok := t.(*tokendef.UserAccessToken); ok {
		encryptedSub := uat.Subject()
		if encryptedSub != "" {
			subToken, err := d.Decrypt(ctx, encryptedSub)
			if err != nil {
				return nil, fmt.Errorf("decrypt sub: %w", err)
			}
			uat.SetIdentity(subToken)
		}
	}

	return t, nil
}

func (d *Decryptor) Decrypt(ctx context.Context, encrypted string) (*paseto.Token, error) {
	kid, err := d.extractor.ExtractKID(encrypted)
	if err != nil {
		return nil, fmt.Errorf("extract kid: %w", err)
	}

	if err := d.ensure(ctx); err != nil {
		return nil, err
	}

	d.mu.RLock()
	sk, ok := d.keys[kid]
	d.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %s", pasetokit.ErrKIDNotFound, kid)
	}

	parser := paseto.NewParserWithoutExpiryCheck()
	t, err := parser.ParseV4Local(sk, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt inner token: %w", err)
	}

	return t, nil
}

func (d *Decryptor) ensure(ctx context.Context) error {
	d.mu.RLock()
	hasKeys := len(d.keys) > 0
	d.mu.RUnlock()
	if hasKeys {
		return nil
	}

	rawKeys, err := d.provider.AllOfKey(ctx, d.extractor.audience)
	if err != nil {
		return fmt.Errorf("load keys: %w", err)
	}
	return d.rebuild(rawKeys)
}

func (d *Decryptor) rebuild(rawKeys [][]byte) error {
	m := make(map[string]paseto.V4SymmetricKey, len(rawKeys))
	for _, raw := range rawKeys {
		sk, err := paseto.V4SymmetricKeyFromBytes(raw)
		if err != nil {
			return fmt.Errorf("parse symmetric key: %w", err)
		}
		lid, err := pasetokit.ComputeLID(sk)
		if err != nil {
			return fmt.Errorf("compute lid: %w", err)
		}
		m[lid] = sk
	}

	d.mu.Lock()
	d.keys = m
	d.mu.Unlock()

	return nil
}
