package cache

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/heliannuuthus/aegis/internal/authenticator/idp"
	pkgredis "github.com/heliannuuthus/pkg/redis"
)

type oauthRedisStub struct {
	pkgredis.Client
	values map[string]any
}

func (s *oauthRedisStub) Set(_ context.Context, key string, value any, _ time.Duration) error {
	if s.values == nil {
		s.values = make(map[string]any)
	}
	s.values[key] = value
	return nil
}

func (s *oauthRedisStub) Eval(_ context.Context, _ string, keys []string, _ ...any) (any, error) {
	value, ok := s.values[keys[0]]
	if !ok {
		return nil, pkgredis.ErrNil
	}
	delete(s.values, keys[0])
	return value, nil
}

func TestOAuthTransactionIsConsumedOnce(t *testing.T) {
	workingDirectory, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd() error = %v", err)
	}
	if err := os.Chdir("../.."); err != nil {
		t.Fatalf("os.Chdir() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(workingDirectory); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	redis := &oauthRedisStub{}
	manager := &Manager{redis: redis}
	tx, err := idp.NewOAuthTransaction("flow-1", idp.TypeGoogle, "https://aegis.example/google/callback")
	if err != nil {
		t.Fatalf("NewOAuthTransaction() error = %v", err)
	}

	if err := manager.SaveOAuthTransaction(context.Background(), tx, time.Minute); err != nil {
		t.Fatalf("SaveOAuthTransaction() error = %v", err)
	}

	got, err := manager.ConsumeOAuthTransaction(context.Background(), tx.State)
	if err != nil {
		t.Fatalf("ConsumeOAuthTransaction() error = %v", err)
	}
	if got.FlowID != tx.FlowID || got.Connection != tx.Connection || got.CodeVerifier != tx.CodeVerifier {
		t.Errorf("consumed transaction = %#v, want %#v", got, tx)
	}

	if _, err := manager.ConsumeOAuthTransaction(context.Background(), tx.State); !errors.Is(err, ErrOAuthTransactionNotFound) {
		t.Fatalf("second ConsumeOAuthTransaction() error = %v, want %v", err, ErrOAuthTransactionNotFound)
	}
}
