//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type fakeAccessValidator struct {
	err error
}

func (v *fakeAccessValidator) Validate(ctx context.Context, request *http.Request) error {
	return v.err
}

func newAccessTestInbound(t *testing.T) *Inbound {
	t.Helper()
	logFactory, err := log.New(log.Options{Options: option.LogOptions{Level: "debug"}})
	if err != nil {
		t.Fatal(err)
	}
	return &Inbound{
		Adapter:     inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		logger:      logFactory.NewLogger("test"),
		accessCache: &accessValidatorCache{values: make(map[string]accessValidator)},
		router:      &testRouter{},
	}
}

func TestValidateAccessConfiguration(t *testing.T) {
	err := validateAccessConfiguration(AccessConfig{
		Required: true,
		AudTag:   []string{"aud"},
	})
	if err == nil {
		t.Fatal("expected access config validation error")
	}
}

func TestRoundTripHTTPAccessDenied(t *testing.T) {
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()
	newAccessValidator = func(access AccessConfig) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	inboundInstance := newAccessTestInbound(t)
	service := ResolvedService{
		Kind: ResolvedServiceHTTP,
		OriginRequest: OriginRequestConfig{
			Access: AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
	}
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()

	respWriter := &fakeConnectResponseWriter{}
	request := &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "http://127.0.0.1:8083",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}
	go func() {
		defer clientSide.Close()
		_, _ = io.Copy(io.Discard, clientSide)
	}()

	inboundInstance.roundTripHTTP(context.Background(), serverSide, respWriter, request, service, &http.Transport{})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}
