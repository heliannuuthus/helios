package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const DefaultPasskeyLabel = "通行密钥"

func InferCredentialLabel(credential *webauthn.Credential) string {
	if credential == nil {
		return DefaultPasskeyLabel
	}

	transports := make(map[protocol.AuthenticatorTransport]struct{}, len(credential.Transport))
	for _, transport := range credential.Transport {
		transports[transport] = struct{}{}
	}

	if _, ok := transports[protocol.USB]; ok {
		return "USB 安全密钥"
	}
	if _, ok := transports[protocol.NFC]; ok {
		return "NFC 安全密钥"
	}
	if _, ok := transports[protocol.BLE]; ok {
		return "蓝牙安全密钥"
	}
	if _, ok := transports[protocol.SmartCard]; ok {
		return "智能卡安全密钥"
	}

	return DefaultPasskeyLabel
}
