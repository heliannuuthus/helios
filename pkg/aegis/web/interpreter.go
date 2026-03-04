package web

import (
	"context"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

// Interpreter verifies tokens and decrypts encrypted sub fields for UAT tokens.
// 按 audience 管理 Decryptor，Verifier 由 Decryptor 内嵌的 extractor 管理。
type Interpreter struct {
	signKeyProvider    key.Provider
	encryptKeyProvider key.Provider

	decryptors map[string]*token.Decryptor
	mu         sync.RWMutex
}

func NewInterpreter(signKeyProvider key.Provider, encryptKeyProvider key.Provider) *Interpreter {
	return &Interpreter{
		signKeyProvider:    signKeyProvider,
		encryptKeyProvider: encryptKeyProvider,
		decryptors:         make(map[string]*token.Decryptor),
	}
}

// Interpret verifies the token signature and decrypts the sub field for UAT tokens.
func (i *Interpreter) Interpret(ctx context.Context, tokenString string) (tokendef.Token, error) {
	pasetoToken, err := tokendef.UnsafeParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := tokendef.GetClientID(pasetoToken)
	if err != nil {
		return nil, err
	}

	audience, err := tokendef.GetAudience(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tokendef.ErrMissingClaims, err)
	}

	tokenType := tokendef.DetectType(pasetoToken)

	decryptor := i.Decryptor(audience)
	pasetoToken, err = decryptor.Verifier(clientID).Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}

	t, err := tokendef.ParseToken(pasetoToken, tokenType)
	if err != nil {
		return nil, err
	}

	if uat, ok := t.(*tokendef.UserAccessToken); ok {
		encryptedSub := uat.GetSubject()
		if encryptedSub != "" {
			subToken, err := decryptor.Decrypt(ctx, encryptedSub)
			if err != nil {
				return nil, fmt.Errorf("decrypt sub: %w", err)
			}
			uat.SetIdentity(subToken)
		}
	}

	return t, nil
}

// Verify only verifies the signature without decrypting the sub field.
func (i *Interpreter) Verify(ctx context.Context, tokenString string) (tokendef.Token, error) {
	pasetoToken, err := tokendef.UnsafeParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	clientID, err := tokendef.GetClientID(pasetoToken)
	if err != nil {
		return nil, err
	}

	audience, err := tokendef.GetAudience(pasetoToken)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", tokendef.ErrMissingClaims, err)
	}

	tokenType := tokendef.DetectType(pasetoToken)

	pasetoToken, err = i.Decryptor(audience).Verifier(clientID).Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return tokendef.ParseToken(pasetoToken, tokenType)
}

func (i *Interpreter) Decryptor(audience string) *token.Decryptor {
	i.mu.RLock()
	d, ok := i.decryptors[audience]
	i.mu.RUnlock()

	if ok {
		return d
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if d, ok := i.decryptors[audience]; ok {
		return d
	}

	d = token.NewDecryptor(i.encryptKeyProvider, audience, i.signKeyProvider)
	i.decryptors[audience] = d
	return d
}
