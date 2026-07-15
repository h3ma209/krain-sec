package honeytoken_test

import (
	"testing"

	"krain-sec/internal/honeytoken"
)

func TestManualFileName(t *testing.T) {
	tok, ok := honeytoken.ManualFileName("VPN_MFA_SignIn_Guide.pdf")
	if !ok || tok != honeytoken.TokenManualVPN {
		t.Fatalf("got %q %v", tok, ok)
	}
	if _, ok := honeytoken.ManualFileName("nope.pdf"); ok {
		t.Fatal("expected miss")
	}
}
