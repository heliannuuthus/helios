package idp

import (
	"testing"
)

func TestNewOAuthTransaction(t *testing.T) {
	t.Parallel()

	tx, err := NewOAuthTransaction("flow-1", TypeGoogle, "https://aegis.example/google/callback")
	if err != nil {
		t.Fatalf("NewOAuthTransaction() error = %v", err)
	}

	if tx.FlowID != "flow-1" {
		t.Errorf("FlowID = %q, want %q", tx.FlowID, "flow-1")
	}
	if tx.Connection != TypeGoogle {
		t.Errorf("Connection = %q, want %q", tx.Connection, TypeGoogle)
	}
	if tx.RedirectURI != "https://aegis.example/google/callback" {
		t.Errorf("RedirectURI = %q", tx.RedirectURI)
	}
	if len(tx.State) != 43 {
		t.Errorf("state length = %d, want 43", len(tx.State))
	}
	if len(tx.CodeVerifier) != 43 {
		t.Errorf("code verifier length = %d, want 43", len(tx.CodeVerifier))
	}
	if got := S256Challenge(tx.CodeVerifier); got != tx.CodeChallenge {
		t.Errorf("code challenge = %q, want %q", tx.CodeChallenge, got)
	}
}

func TestNewOAuthTransactionRequiresContext(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		flowID      string
		connection  string
		redirectURI string
	}{
		{name: "missing flow", connection: TypeGoogle, redirectURI: "https://aegis.example/google/callback"},
		{name: "missing connection", flowID: "flow-1", redirectURI: "https://aegis.example/google/callback"},
		{name: "missing redirect uri", flowID: "flow-1", connection: TypeGoogle},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewOAuthTransaction(tt.flowID, tt.connection, tt.redirectURI); err == nil {
				t.Fatal("NewOAuthTransaction() error = nil, want error")
			}
		})
	}
}
