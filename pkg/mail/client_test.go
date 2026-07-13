package mail

import "testing"

func TestNewClientRejectsIncompleteConfiguration(t *testing.T) {
	tests := []struct {
		name string
		cfg  *ClientConfig
	}{
		{name: "nil config"},
		{name: "missing host", cfg: &ClientConfig{Username: "user", Password: "secret"}},
		{name: "missing username", cfg: &ClientConfig{Host: "smtp.example.com", Password: "secret"}},
		{name: "missing password", cfg: &ClientConfig{Host: "smtp.example.com", Username: "user"}},
		{name: "invalid port", cfg: &ClientConfig{Host: "smtp.example.com", Port: 70000, Username: "user", Password: "secret"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClient(tt.cfg); err == nil {
				t.Fatal("expected configuration error")
			}
		})
	}
}
