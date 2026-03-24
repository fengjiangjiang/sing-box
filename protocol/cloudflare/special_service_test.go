//go:build with_cloudflare_tunnel

package cloudflare

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/ws"
	"github.com/sagernet/ws/wsutil"
)

type fakeConnectResponseWriter struct {
	status  int
	headers http.Header
	err     error
	done    chan struct{}
}

func (w *fakeConnectResponseWriter) WriteResponse(responseError error, metadata []Metadata) error {
	w.err = responseError
	w.headers = make(http.Header)
	for _, entry := range metadata {
		switch {
		case entry.Key == metadataHTTPStatus:
			status, _ := strconv.Atoi(entry.Val)
			w.status = status
		case len(entry.Key) > len(metadataHTTPHeader)+1 && entry.Key[:len(metadataHTTPHeader)+1] == metadataHTTPHeader+":":
			w.headers.Add(entry.Key[len(metadataHTTPHeader)+1:], entry.Val)
		}
	}
	if w.done != nil {
		close(w.done)
		w.done = nil
	}
	return nil
}

func newSpecialServiceInbound(t *testing.T) *Inbound {
	t.Helper()
	logFactory, err := log.New(log.Options{Options: option.LogOptions{Level: "debug"}})
	if err != nil {
		t.Fatal(err)
	}
	configManager, err := NewConfigManager(option.CloudflareTunnelInboundOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeCloudflareTunnel, "test"),
		router:        &testRouter{},
		logger:        logFactory.NewLogger("test"),
		configManager: configManager,
	}
}

func TestHandleBastionStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	inboundInstance := newSpecialServiceInbound(t)
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
			{Key: metadataHTTPHeader + ":Cf-Access-Jump-Destination", Val: listener.Addr().String()},
		},
	}
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		defer close(done)
		inboundInstance.handleBastionStream(context.Background(), serverSide, respWriter, request, adapter.InboundContext{})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bastion connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
	}
	if respWriter.headers.Get("Sec-WebSocket-Accept") == "" {
		t.Fatal("expected websocket accept header")
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, opCode, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if opCode != ws.OpBinary {
		t.Fatalf("expected binary frame, got %v", opCode)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echoed payload, got %q", string(data))
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bastion stream did not exit")
	}
}

func TestHandleSocksProxyStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(conn)
		}
	}()

	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()

	inboundInstance := newSpecialServiceInbound(t)
	request := &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}

	done := make(chan struct{})
	go func() {
		defer close(done)
		inboundInstance.handleSocksProxyStream(context.Background(), serverSide, respWriter, request, adapter.InboundContext{})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for socks-proxy connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string([]byte{5, 0}) {
		t.Fatalf("unexpected auth response: %v", data)
	}

	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	requestBytes := []byte{5, 1, 0, 1}
	requestBytes = append(requestBytes, net.ParseIP(host).To4()...)
	requestBytes = append(requestBytes, byte(port>>8), byte(port))
	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, requestBytes); err != nil {
		t.Fatal(err)
	}
	data, _, err = wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 10 || data[1] != 0 {
		t.Fatalf("unexpected connect response: %v", data)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, _, err = wsutil.ReadServerData(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echoed payload, got %q", string(data))
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}
