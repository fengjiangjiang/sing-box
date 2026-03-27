//go:build with_cloudflared

package cloudflare

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

type noopRouteConnectionRouter struct {
	testRouter
}

func (r *noopRouteConnectionRouter) RouteConnectionEx(_ context.Context, conn net.Conn, _ adapter.InboundContext, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	onClose(nil)
}

func TestOriginTLSServerName(t *testing.T) {
	t.Run("origin server name overrides host", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{
			OriginServerName: "origin.example.com",
			MatchSNIToHost:   true,
		}, "request.example.com")
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host strips port", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, "request.example.com:443")
		if serverName != "request.example.com" {
			t.Fatalf("expected request.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host uses http host header", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, effectiveOriginHost(OriginRequestConfig{
			HTTPHostHeader: "origin.example.com",
			MatchSNIToHost: true,
		}, "request.example.com"))
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("match sni to host strips port from http host header", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{
			MatchSNIToHost: true,
		}, effectiveOriginHost(OriginRequestConfig{
			HTTPHostHeader: "origin.example.com:8443",
			MatchSNIToHost: true,
		}, "request.example.com"))
		if serverName != "origin.example.com" {
			t.Fatalf("expected origin.example.com, got %s", serverName)
		}
	})

	t.Run("disabled match keeps empty server name", func(t *testing.T) {
		serverName := originTLSServerName(OriginRequestConfig{}, "request.example.com")
		if serverName != "" {
			t.Fatalf("expected empty server name, got %s", serverName)
		}
	})
}

func TestNewOriginTLSConfigErrorsOnMissingCAPool(t *testing.T) {
	originalBaseLoader := loadOriginCABasePool
	loadOriginCABasePool = func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}
	defer func() {
		loadOriginCABasePool = originalBaseLoader
	}()

	_, err := newOriginTLSConfig(OriginRequestConfig{
		CAPool: "/path/does/not/exist.pem",
	}, "request.example.com")
	if err == nil {
		t.Fatal("expected error for missing ca pool")
	}
}

func TestNewOriginTLSConfigAppendsCustomCAInsteadOfReplacingBasePool(t *testing.T) {
	basePEM, baseCert := createTestCertificatePEM(t, "base")
	customPEM, customCert := createTestCertificatePEM(t, "custom")

	basePool := x509.NewCertPool()
	if !basePool.AppendCertsFromPEM(basePEM) {
		t.Fatal("expected base cert to append")
	}

	originalBaseLoader := loadOriginCABasePool
	loadOriginCABasePool = func() (*x509.CertPool, error) {
		return basePool, nil
	}
	defer func() {
		loadOriginCABasePool = originalBaseLoader
	}()

	caFile := writeTempPEM(t, customPEM)
	tlsConfig, err := newOriginTLSConfig(OriginRequestConfig{
		CAPool: caFile,
	}, "request.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if tlsConfig.RootCAs == nil {
		t.Fatal("expected root CA pool")
	}
	subjects := tlsConfig.RootCAs.Subjects()
	if len(subjects) != 2 {
		t.Fatalf("expected 2 subjects, got %d", len(subjects))
	}
	if !containsSubject(subjects, baseCert.RawSubject) {
		t.Fatal("expected base subject to remain in pool")
	}
	if !containsSubject(subjects, customCert.RawSubject) {
		t.Fatal("expected custom subject to be appended to pool")
	}
}

func TestOriginTransportUsesProxyFromEnvironmentOnly(t *testing.T) {
	originalProxyFromEnvironment := proxyFromEnvironment
	proxyFromEnvironment = func(request *http.Request) (*url.URL, error) {
		return url.Parse("http://proxy.example.com:8080")
	}
	defer func() {
		proxyFromEnvironment = originalProxyFromEnvironment
	}()

	inbound := &Inbound{}
	transport, cleanup, err := inbound.newDirectOriginTransport(ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		OriginRequest: OriginRequestConfig{
			ProxyAddress: "127.0.0.1",
			ProxyPort:    8081,
			ProxyType:    "http",
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	proxyURL, err := transport.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://proxy.example.com:8080" {
		t.Fatalf("expected environment proxy URL, got %#v", proxyURL)
	}
}

func TestNewDirectOriginTransportNoHappyEyeballs(t *testing.T) {
	inbound := &Inbound{}
	transport, cleanup, err := inbound.newDirectOriginTransport(ResolvedService{
		Kind:     ResolvedServiceUnix,
		UnixPath: "/tmp/test.sock",
		OriginRequest: OriginRequestConfig{
			NoHappyEyeballs: true,
		},
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if transport.Proxy == nil {
		t.Fatal("expected proxy function to be configured from environment")
	}
	if transport.DialContext == nil {
		t.Fatal("expected custom direct dial context")
	}
}

func TestNewRouterOriginTransportPropagatesTLSConfigError(t *testing.T) {
	originalBaseLoader := loadOriginCABasePool
	loadOriginCABasePool = func() (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}
	defer func() {
		loadOriginCABasePool = originalBaseLoader
	}()

	inbound := &Inbound{}
	_, _, err := inbound.newRouterOriginTransport(context.Background(), adapter.InboundContext{}, OriginRequestConfig{
		CAPool: "/path/does/not/exist.pem",
	}, "")
	if err == nil {
		t.Fatal("expected transport build error")
	}
}

func TestNewRouterOriginTransportUsesCloudflaredDefaults(t *testing.T) {
	inbound := &Inbound{
		router: &noopRouteConnectionRouter{},
	}
	transport, cleanup, err := inbound.newRouterOriginTransport(context.Background(), adapter.InboundContext{}, OriginRequestConfig{}, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	if transport.ExpectContinueTimeout != time.Second {
		t.Fatalf("expected ExpectContinueTimeout=1s, got %s", transport.ExpectContinueTimeout)
	}
	if transport.DisableCompression {
		t.Fatal("expected compression to remain enabled by default")
	}
}

func TestNormalizeOriginRequestSetsKeepAliveAndEmptyUserAgent(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.com/path", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	request = normalizeOriginRequest(ConnectionTypeHTTP, request, OriginRequestConfig{})
	if connection := request.Header.Get("Connection"); connection != "keep-alive" {
		t.Fatalf("expected keep-alive connection header, got %q", connection)
	}
	if values, exists := request.Header["User-Agent"]; !exists || len(values) != 1 || values[0] != "" {
		t.Fatalf("expected empty User-Agent header, got %#v", request.Header["User-Agent"])
	}
}

func TestNormalizeOriginRequestDisableChunkedEncoding(t *testing.T) {
	request, err := http.NewRequest(http.MethodPost, "https://example.com/path", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Length", "7")

	request = normalizeOriginRequest(ConnectionTypeHTTP, request, OriginRequestConfig{
		DisableChunkedEncoding: true,
	})
	if len(request.TransferEncoding) != 2 || request.TransferEncoding[0] != "gzip" || request.TransferEncoding[1] != "deflate" {
		t.Fatalf("unexpected transfer encoding: %#v", request.TransferEncoding)
	}
	if request.ContentLength != 7 {
		t.Fatalf("expected content length 7, got %d", request.ContentLength)
	}
}

func TestNormalizeOriginRequestWebsocket(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "https://example.com/path", io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}

	request = normalizeOriginRequest(ConnectionTypeWebsocket, request, OriginRequestConfig{})
	if connection := request.Header.Get("Connection"); connection != "Upgrade" {
		t.Fatalf("expected websocket connection header, got %q", connection)
	}
	if upgrade := request.Header.Get("Upgrade"); upgrade != "websocket" {
		t.Fatalf("expected websocket upgrade header, got %q", upgrade)
	}
	if version := request.Header.Get("Sec-Websocket-Version"); version != "13" {
		t.Fatalf("expected websocket version 13, got %q", version)
	}
	if request.ContentLength != 0 {
		t.Fatalf("expected websocket content length 0, got %d", request.ContentLength)
	}
	if request.Body != nil {
		t.Fatal("expected websocket body to be nil")
	}
}

func createTestCertificatePEM(t *testing.T, commonName string) ([]byte, *x509.Certificate) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate
}

func writeTempPEM(t *testing.T, pemData []byte) string {
	t.Helper()
	path := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func containsSubject(subjects [][]byte, want []byte) bool {
	for _, subject := range subjects {
		if bytes.Equal(subject, want) {
			return true
		}
	}
	return false
}
