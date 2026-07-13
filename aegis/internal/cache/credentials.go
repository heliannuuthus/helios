package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/go-json-experiment/json"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/pkg/helpers"
)

type TOTPEnrollmentSession struct {
	OpenID string `json:"openid"`
	Secret string `json:"secret"`
	Label  string `json:"label"`
}

func (cm *Manager) SaveTOTPEnrollmentSession(ctx context.Context, session *TOTPEnrollmentSession) (string, error) {
	uid := helpers.GenerateID(16)
	data, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	if err := cm.redis.Set(ctx, cm.totpEnrollmentKey(uid), string(data), config.GetTOTPEnrollmentExpiresIn()); err != nil {
		return "", err
	}
	return uid, nil
}

func (cm *Manager) GetTOTPEnrollmentSession(ctx context.Context, uid string) (*TOTPEnrollmentSession, error) {
	data, err := cm.redis.Get(ctx, cm.totpEnrollmentKey(uid))
	if err != nil {
		return nil, fmt.Errorf("totp enrollment session not found")
	}

	var session TOTPEnrollmentSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (cm *Manager) DeleteTOTPEnrollmentSession(ctx context.Context, uid string) error {
	return cm.redis.Del(ctx, cm.totpEnrollmentKey(uid))
}

func (cm *Manager) totpEnrollmentKey(uid string) string {
	return config.GetCacheKeyPrefix("totp_enrollment") + uid
}

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

	return cm.redis.Set(ctx, cm.webAuthnCeremonyKey(ceremony.ID), string(data), ttl)
}

func (cm *Manager) GetWebAuthnCeremony(ctx context.Context, ceremonyID string) (*WebAuthnCeremony, error) {
	if ceremonyID == "" {
		return nil, fmt.Errorf("webauthn ceremony id is required")
	}

	data, err := cm.redis.Get(ctx, cm.webAuthnCeremonyKey(ceremonyID))
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

func (cm *Manager) DeleteWebAuthnCeremony(ctx context.Context, ceremonyID string) error {
	if ceremonyID == "" {
		return fmt.Errorf("webauthn ceremony id is required")
	}
	return cm.redis.Del(ctx, cm.webAuthnCeremonyKey(ceremonyID))
}

func (cm *Manager) webAuthnCeremonyKey(ceremonyID string) string {
	return config.GetCacheKeyPrefix("webauthn-ceremony") + ceremonyID
}
