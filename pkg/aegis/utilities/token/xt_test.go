package token

import "testing"

func TestChannelTypeNames(t *testing.T) {
	tests := map[ChannelType]string{
		ChannelTypeEmailOTP: "email-code",
		ChannelTypeSmsOTP:   "sms-code",
		ChannelTypeTgOTP:    "telegram-code",
	}

	for input, want := range tests {
		if got := string(input); got != want {
			t.Fatalf("channel type = %q, want %q", got, want)
		}
	}
}

func TestCodeChannelTypesAreVerificationTypes(t *testing.T) {
	for _, channelType := range []ChannelType{
		ChannelTypeEmailOTP,
		ChannelTypeSmsOTP,
		ChannelTypeTgOTP,
	} {
		if !channelType.IsVerification() {
			t.Fatalf("%q should be accepted as verification channel type", channelType)
		}
	}
}
