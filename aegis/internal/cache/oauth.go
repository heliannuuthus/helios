package cache

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-json-experiment/json"

	"github.com/heliannuuthus/aegis/config"
	"github.com/heliannuuthus/aegis/internal/authenticator/idp"
	pkgredis "github.com/heliannuuthus/pkg/redis"
)

// ErrOAuthTransactionNotFound indicates an invalid, expired, or already-consumed state.
var ErrOAuthTransactionNotFound = errors.New("oauth transaction not found")

const consumeOAuthTransactionScript = `
local value = redis.call("GET", KEYS[1])
if not value then
  return nil
end
redis.call("DEL", KEYS[1])
return value
`

// SaveOAuthTransaction persists a short-lived upstream OAuth transaction by its random state.
func (cm *Manager) SaveOAuthTransaction(ctx context.Context, tx *idp.OAuthTransaction, ttl time.Duration) error {
	if tx == nil || tx.State == "" || ttl <= 0 {
		return errors.New("oauth transaction or ttl is invalid")
	}
	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("marshal oauth transaction: %w", err)
	}
	return cm.redis.Set(ctx, oauthTransactionKey(tx.State), string(data), ttl)
}

// ConsumeOAuthTransaction atomically reads and deletes a state transaction.
func (cm *Manager) ConsumeOAuthTransaction(ctx context.Context, state string) (*idp.OAuthTransaction, error) {
	if state == "" {
		return nil, ErrOAuthTransactionNotFound
	}
	value, err := cm.redis.Eval(ctx, consumeOAuthTransactionScript, []string{oauthTransactionKey(state)})
	if err != nil {
		if errors.Is(err, pkgredis.ErrNil) {
			return nil, ErrOAuthTransactionNotFound
		}
		return nil, fmt.Errorf("consume oauth transaction: %w", err)
	}

	var encoded []byte
	switch v := value.(type) {
	case string:
		encoded = []byte(v)
	case []byte:
		encoded = v
	default:
		return nil, fmt.Errorf("consume oauth transaction: unexpected redis value %T", value)
	}

	var tx idp.OAuthTransaction
	if err := json.Unmarshal(encoded, &tx); err != nil {
		return nil, fmt.Errorf("unmarshal oauth transaction: %w", err)
	}
	return &tx, nil
}

func oauthTransactionKey(state string) string {
	return config.GetCacheKeyPrefix("oauth_state") + state
}
