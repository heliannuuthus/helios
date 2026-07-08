package webauthn

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestInferCredentialLabel(t *testing.T) {
	tests := []struct {
		name       string
		transport  []protocol.AuthenticatorTransport
		want       string
		credential *webauthn.Credential
	}{
		{name: "nil credential", want: DefaultPasskeyLabel},
		{name: "usb key", transport: []protocol.AuthenticatorTransport{protocol.USB}, want: "USB 安全密钥"},
		{name: "nfc key", transport: []protocol.AuthenticatorTransport{protocol.NFC}, want: "NFC 安全密钥"},
		{name: "ble key", transport: []protocol.AuthenticatorTransport{protocol.BLE}, want: "蓝牙安全密钥"},
		{name: "internal passkey", transport: []protocol.AuthenticatorTransport{protocol.Internal}, want: DefaultPasskeyLabel},
		{name: "empty transport", transport: nil, want: DefaultPasskeyLabel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			credential := tt.credential
			if credential == nil && tt.name != "nil credential" {
				credential = &webauthn.Credential{Transport: tt.transport}
			}
			if got := InferCredentialLabel(credential); got != tt.want {
				t.Fatalf("InferCredentialLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}
