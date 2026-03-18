//go:build with_cloudflare_tunnel

package cloudflare

import (
	"encoding/base64"
	"os"
	"path/filepath"
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

func TestParseCredentialFile(t *testing.T) {
	tunnelID := uuid.New()
	content := `{"AccountTag":"acct","TunnelSecret":"c2VjcmV0","TunnelID":"` + tunnelID.String() + `"}`
	path := filepath.Join(t.TempDir(), "creds.json")
	err := os.WriteFile(path, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	credentials, err := parseCredentialFile(path)
	if err != nil {
		t.Fatal("parseCredentialFile: ", err)
	}
	if credentials.AccountTag != "acct" {
		t.Error("expected AccountTag acct, got ", credentials.AccountTag)
	}
	if credentials.TunnelID != tunnelID {
		t.Error("expected TunnelID ", tunnelID, ", got ", credentials.TunnelID)
	}
}

func TestParseCredentialFileMissingTunnelID(t *testing.T) {
	content := `{"AccountTag":"acct","TunnelSecret":"c2VjcmV0","TunnelID":"00000000-0000-0000-0000-000000000000"}`
	path := filepath.Join(t.TempDir(), "creds.json")
	err := os.WriteFile(path, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = parseCredentialFile(path)
	if err == nil {
		t.Fatal("expected error for missing tunnel ID")
	}
}

func TestParseCredentialsBothSpecified(t *testing.T) {
	_, err := parseCredentials("sometoken", "/some/path")
	if err == nil {
		t.Fatal("expected error when both specified")
	}
}

func TestParseCredentialsNoneSpecified(t *testing.T) {
	_, err := parseCredentials("", "")
	if err == nil {
		t.Fatal("expected error when none specified")
	}
}
