package web

import (
	"context"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	"github.com/heliannuuthus/helios/pkg/aegis/token"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

var ErrUnsupportedAudience = fmt.Errorf("unsupported audience")

// Interpreter verifies tokens and decrypts encrypted sub fields for UAT tokens.
type Interpreter struct {
	signKeyStore    *key.Store
	encryptKeyStore *key.Store

	verifiers  map[string]*token.Verifier
	decryptors map[string]*token.Decryptor
	mu         sync.RWMutex
}

func NewInterpreter(signKeyStore *key.Store, encryptKeyStore *key.Store) *Interpreter {
	return &Interpreter{
		signKeyStore:    signKeyStore,
		encryptKeyStore: encryptKeyStore,
		verifiers:       make(map[string]*token.Verifier),
		decryptors:      make(map[string]*token.Decryptor),
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

	pasetoToken, err = i.Verifier(clientID).Verify(ctx, tokenString)
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
			userInfo, err := i.decryptUserSub(ctx, encryptedSub, audience)
			if err != nil {
				return nil, err
			}
			uat.SetUserInfo(userInfo)
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

	tokenType := tokendef.DetectType(pasetoToken)

	pasetoToken, err = i.Verifier(clientID).Verify(ctx, tokenString)
	if err != nil {
		return nil, err
	}
	return tokendef.ParseToken(pasetoToken, tokenType)
}

func (i *Interpreter) Verifier(clientID string) *token.Verifier {
	i.mu.RLock()
	v, ok := i.verifiers[clientID]
	i.mu.RUnlock()

	if ok {
		return v
	}

	i.mu.Lock()
	defer i.mu.Unlock()

	if v, ok := i.verifiers[clientID]; ok {
		return v
	}

	v = token.NewVerifier(i.signKeyStore, clientID)
	i.verifiers[clientID] = v
	return v
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

	d = token.NewDecryptor(i.encryptKeyStore, audience)
	i.decryptors[audience] = d
	return d
}

func (i *Interpreter) decryptUserSub(ctx context.Context, encryptedSub, audience string) (*tokendef.UserInfo, error) {
	decryptor := i.Decryptor(audience)

	claimsJSON, err := decryptor.Decrypt(ctx, encryptedSub)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	return tokendef.UnmarshalUserInfo(claimsJSON)
}
