package hermes

import (
	"strings"
	"testing"
)

func TestValidateDomainName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "trims whitespace", value: "  Consumer  ", want: "Consumer"},
		{name: "rejects blank", value: "  ", wantErr: true},
		{name: "accepts 128 unicode characters", value: strings.Repeat("域", 128), want: strings.Repeat("域", 128)},
		{name: "rejects more than 128 unicode characters", value: strings.Repeat("域", 129), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateDomainName(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDomainName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("validateDomainName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateDomainDescription(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "trims whitespace", value: "  Identity boundary  ", want: "Identity boundary"},
		{name: "accepts empty", value: "", want: ""},
		{name: "accepts 512 unicode characters", value: strings.Repeat("域", 512), want: strings.Repeat("域", 512)},
		{name: "rejects more than 512 unicode characters", value: strings.Repeat("域", 513), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := validateDomainDescription(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateDomainDescription() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("validateDomainDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}
