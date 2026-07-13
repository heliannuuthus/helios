package google

import (
	"net/url"
	"testing"
)

func TestBuildAuthorizationURL(t *testing.T) {
	t.Parallel()

	raw, err := buildAuthorizationURL(
		"google-client",
		"https://aegis.example/google/callback",
		"oauth-state",
		"pkce-challenge",
	)
	if err != nil {
		t.Fatalf("buildAuthorizationURL() error = %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if u.Scheme != "https" || u.Host != "accounts.google.com" || u.Path != "/o/oauth2/v2/auth" {
		t.Errorf("authorization endpoint = %s", u.String())
	}

	query := u.Query()
	wants := map[string]string{
		"client_id":             "google-client",
		"redirect_uri":          "https://aegis.example/google/callback",
		"response_type":         "code",
		"scope":                 "openid email profile",
		"state":                 "oauth-state",
		"code_challenge":        "pkce-challenge",
		"code_challenge_method": "S256",
	}
	for key, want := range wants {
		if got := query.Get(key); got != want {
			t.Errorf("query[%s] = %q, want %q", key, got, want)
		}
	}
}
