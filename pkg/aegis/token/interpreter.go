package token

import (
	"context"
	"fmt"
	"sync"

	"github.com/heliannuuthus/helios/pkg/aegis/key"
	tokendef "github.com/heliannuuthus/helios/pkg/aegis/utils/token"
)

var ErrUnsupportedAudience = fmt.Errorf("unsupported audience")

// Interpreter verifies tokens and decrypts encrypted sub fields for UAT tokens.
type Interpreter struct {
	signKeyStore    *key.Store
	encryptKeyStore *key.Store

	verifiers  map[string]*Verifier
	decryptors map[string]*Decryptor
	mu         sync.RWMutex
}

func NewInterpreter(signKeyStore *key.Store, encryptKeyStore *key.Store) *Interpreter {
	return &Interpreter{
		signKeyStore:    signKeyStore,
		encryptKeyStore: encryptKeyStore,
		verifiers:       make(map[string]*Verifier),
		decryptors:      make(map[string]*Decryptor),
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

func (i *Interpreter) Verifier(clientID string) *Verifier {
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

	v = NewVerifier(i.signKeyStore, clientID)
	i.verifiers[clientID] = v
	return v
}

func (i *Interpreter) Decryptor(audience string) *Decryptor {
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

	d = NewDecryptor(i.encryptKeyStore, audience)
	i.decryptors[audience] = d
	return d
}

func (i *Interpreter) decryptUserSub(ctx context.Context, encryptedSub, audience string) (*tokendef.UserInfo, error) {
	decryptor := i.Decryptor(audience)

	claimsJSON, _, err := decryptor.Decrypt(ctx, encryptedSub)
	if err != nil {
		return nil, fmt.Errorf("decrypt sub: %w", err)
	}

	return tokendef.UnmarshalUserInfo(claimsJSON)
}
