//go:build with_cloudflared

package cloudflare

import (
	"context"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
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
		Adapter:       inbound.NewAdapter(C.TypeCloudflared, "test"),
		logger:        logFactory.NewLogger("test"),
		accessCache:   &accessValidatorCache{values: make(map[string]accessValidator), dialer: N.SystemDialer},
		router:        &testRouter{},
		controlDialer: N.SystemDialer,
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
	newAccessValidator = func(access AccessConfig, dialer N.Dialer) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	inboundInstance := newAccessTestInbound(t)
	respWriter := &fakeConnectResponseWriter{}
	request := &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "http://127.0.0.1:8083/test",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}
	inboundInstance.handleHTTPService(context.Background(), nil, respWriter, request, adapter.InboundContext{}, ResolvedService{
		Kind:        ResolvedServiceHTTP,
		Destination: M.ParseSocksaddr("127.0.0.1:8083"),
		OriginRequest: OriginRequestConfig{
			Access: AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
	})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}

func TestHandleHTTPServiceStatusAccessDenied(t *testing.T) {
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()
	newAccessValidator = func(access AccessConfig, dialer N.Dialer) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	inboundInstance := newAccessTestInbound(t)
	respWriter := &fakeConnectResponseWriter{}
	request := &ConnectRequest{
		Type: ConnectionTypeHTTP,
		Dest: "https://example.com/status",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
		},
	}
	inboundInstance.handleHTTPService(context.Background(), nil, respWriter, request, adapter.InboundContext{}, ResolvedService{
		Kind: ResolvedServiceStatus,
		OriginRequest: OriginRequestConfig{
			Access: AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
		StatusCode: 404,
	})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}

func TestHandleHTTPServiceStreamAccessDenied(t *testing.T) {
	originalFactory := newAccessValidator
	defer func() {
		newAccessValidator = originalFactory
	}()
	newAccessValidator = func(access AccessConfig, dialer N.Dialer) (accessValidator, error) {
		return &fakeAccessValidator{err: E.New("forbidden")}, nil
	}

	inboundInstance := newAccessTestInbound(t)
	respWriter := &fakeConnectResponseWriter{}
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Dest: "https://example.com/ws",
		Metadata: []Metadata{
			{Key: metadataHTTPMethod, Val: http.MethodGet},
			{Key: metadataHTTPHost, Val: "example.com"},
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
	inboundInstance.handleHTTPService(context.Background(), nil, respWriter, request, adapter.InboundContext{}, ResolvedService{
		Kind:        ResolvedServiceStream,
		Destination: M.ParseSocksaddr("127.0.0.1:8080"),
		OriginRequest: OriginRequestConfig{
			Access: AccessConfig{
				Required: true,
				TeamName: "team",
			},
		},
	})
	if respWriter.status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", respWriter.status)
	}
}
