package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/aegis/config"
)

// WebAuthnCeremony is the temporary state shared between WebAuthn begin and finish steps.
type WebAuthnCeremony struct {
	ID          string                `json:"id"`
	Operation   string                `json:"operation"`
	OpenID      string                `json:"openid"`
	Challenge   string                `json:"challenge"`
	SessionData *webauthn.SessionData `json:"session_data"`
	CreatedAt   time.Time             `json:"created_at"`
	ExpiresAt   time.Time             `json:"expires_at"`
}

// SaveWebAuthnCeremony stores a WebAuthn ceremony in Redis.
func (cm *Manager) SaveWebAuthnCeremony(ctx context.Context, ceremony *WebAuthnCeremony, ttl time.Duration) error {
	if ceremony == nil {
		return fmt.Errorf("webauthn ceremony is required")
	}
	if ceremony.ID == "" {
		return fmt.Errorf("webauthn ceremony id is required")
	}
	if ceremony.SessionData == nil {
		return fmt.Errorf("webauthn ceremony session data is required")
	}
	if ttl <= 0 {
		ttl = config.GetChallengeBusinessExpiresIn()
	}

	now := time.Now()
	ceremony.CreatedAt = now
	ceremony.ExpiresAt = now.Add(ttl)
	if ceremony.Challenge == "" {
		ceremony.Challenge = ceremony.SessionData.Challenge
	}

	data, err := json.Marshal(ceremony)
	if err != nil {
		return fmt.Errorf("marshal webauthn ceremony: %w", err)
	}

	prefix := config.GetCacheKeyPrefix("webauthn-ceremony")
	return cm.redis.Set(ctx, prefix+ceremony.ID, string(data), ttl)
}

// GetWebAuthnCeremony loads a WebAuthn ceremony from Redis.
func (cm *Manager) GetWebAuthnCeremony(ctx context.Context, ceremonyID string) (*WebAuthnCeremony, error) {
	if ceremonyID == "" {
		return nil, fmt.Errorf("webauthn ceremony id is required")
	}

	prefix := config.GetCacheKeyPrefix("webauthn-ceremony")
	data, err := cm.redis.Get(ctx, prefix+ceremonyID)
	if err != nil {
		return nil, fmt.Errorf("webauthn ceremony not found")
	}

	var ceremony WebAuthnCeremony
	if err := json.Unmarshal([]byte(data), &ceremony); err != nil {
		return nil, fmt.Errorf("unmarshal webauthn ceremony: %w", err)
	}
	if ceremony.SessionData == nil {
		return nil, fmt.Errorf("webauthn ceremony session data not found")
	}
	if time.Now().After(ceremony.ExpiresAt) {
		return nil, fmt.Errorf("webauthn ceremony expired")
	}
	return &ceremony, nil
}

// DeleteWebAuthnCeremony removes a WebAuthn ceremony from Redis.
func (cm *Manager) DeleteWebAuthnCeremony(ctx context.Context, ceremonyID string) error {
	if ceremonyID == "" {
		return fmt.Errorf("webauthn ceremony id is required")
	}

	prefix := config.GetCacheKeyPrefix("webauthn-ceremony")
	return cm.redis.Del(ctx, prefix+ceremonyID)
}
