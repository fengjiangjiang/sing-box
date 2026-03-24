//go:build with_cloudflared

package cloudflare

import (
	"encoding/base64"
	"testing"

	"github.com/google/uuid"
)

func TestParseToken(t *testing.T) {
	tunnelID := uuid.New()
	secret := []byte("test-secret-32-bytes-long-xxxxx")
	tokenJSON := `{"a":"account123","t":"` + tunnelID.String() + `","s":"` + base64.StdEncoding.EncodeToString(secret) + `"}`
	token := base64.StdEncoding.EncodeToString([]byte(tokenJSON))

	credentials, err := parseToken(token)
	if err != nil {
		t.Fatal("parseToken: ", err)
	}
	if credentials.AccountTag != "account123" {
		t.Error("expected AccountTag account123, got ", credentials.AccountTag)
	}
	if credentials.TunnelID != tunnelID {
		t.Error("expected TunnelID ", tunnelID, ", got ", credentials.TunnelID)
	}
}

func TestParseTokenInvalidBase64(t *testing.T) {
	_, err := parseToken("not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

func TestParseTokenInvalidJSON(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte("{bad json"))
	_, err := parseToken(token)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
