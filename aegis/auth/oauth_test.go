package auth

import (
	"net/url"
	"testing"

	"github.com/heliannuuthus/aegis/internal/authenticator/idp"
)

func TestValidateOAuthAuthorizationURL(t *testing.T) {
	t.Parallel()

	tx := &idp.OAuthTransaction{
		RedirectURI:   "https://aegis.heliannuuthus.com/google/callback",
		State:         "state-value",
		CodeChallenge: "challenge-value",
	}
	query := url.Values{
		"client_id":             {"client-id"},
		"redirect_uri":          {tx.RedirectURI},
		"response_type":         {"code"},
		"state":                 {tx.State},
		"code_challenge":        {tx.CodeChallenge},
		"code_challenge_method": {"S256"},
	}

	tests := []struct {
		name       string
		connection string
		rawURL     string
		wantErr    bool
	}{
		{
			name:       "google transaction",
			connection: idp.TypeGoogle,
			rawURL:     "https://accounts.google.com/o/oauth2/v2/auth?" + query.Encode(),
		},
		{
			name:       "github transaction",
			connection: idp.TypeGithub,
			rawURL:     "https://github.com/login/oauth/authorize?" + query.Encode(),
		},
		{
			name:       "lookalike host",
			connection: idp.TypeGoogle,
			rawURL:     "https://accounts.google.com.evil.example/o/oauth2/v2/auth?" + query.Encode(),
			wantErr:    true,
		},
		{
			name:       "mismatched state",
			connection: idp.TypeGoogle,
			rawURL:     "https://accounts.google.com/o/oauth2/v2/auth?" + withQueryValue(query, "state", "other").Encode(),
			wantErr:    true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateOAuthAuthorizationURL(test.connection, test.rawURL, tx)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateOAuthAuthorizationURL() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func withQueryValue(values url.Values, key, value string) url.Values {
	clone := url.Values{}
	for queryKey, queryValues := range values {
		clone[queryKey] = append([]string(nil), queryValues...)
	}
	clone.Set(key, value)
	return clone
}
