package guard

import (
	"context"
	"errors"
	"testing"

	"github.com/heliannuuthus/pkg/aegis/utilities/key"
)

func TestNewServiceTokenManagerValidatesConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		audience string
		seed     []byte
	}{
		{name: "missing endpoint", audience: "hermes", seed: make([]byte, serviceSeedSize)},
		{name: "missing audience", endpoint: "https://aegis.example.com/api", seed: make([]byte, serviceSeedSize)},
		{name: "invalid seed", endpoint: "https://aegis.example.com/api", audience: "hermes", seed: make([]byte, serviceSeedSize-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewServiceTokenManager(tt.endpoint, tt.audience, tt.seed); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}

func TestNewServiceTokenManagerScopesSeedToAudience(t *testing.T) {
	previous := globalManager
	t.Cleanup(func() { globalManager = previous })

	seed := make([]byte, serviceSeedSize)
	if err := NewServiceTokenManager("https://aegis.example.com/api", "hermes", seed); err != nil {
		t.Fatalf("initialize token manager: %v", err)
	}

	if GetTokenManager() == nil {
		t.Fatal("token manager was not initialized")
	}

	provider := newServiceSeedProvider("hermes", seed)
	if _, err := provider.OneOfKey(context.Background(), "zwei"); !errors.Is(err, key.ErrNotFound) {
		t.Fatalf("expected audience-scoped key provider, got %v", err)
	}
}

func TestNewGinRequiresInitializedTokenManager(t *testing.T) {
	previous := globalManager
	globalManager = nil
	t.Cleanup(func() { globalManager = previous })

	if _, err := NewGin("hermes"); err == nil {
		t.Fatal("expected missing token manager error")
	}
	if err := NewServiceTokenManager("https://aegis.example.com/api", "hermes", make([]byte, serviceSeedSize)); err != nil {
		t.Fatalf("initialize token manager: %v", err)
	}
	if _, err := NewGin("hermes"); err != nil {
		t.Fatalf("NewGin returned error after initialization: %v", err)
	}
}
