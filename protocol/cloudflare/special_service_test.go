//go:build with_cloudflared

package cloudflare

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
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
	return newSpecialServiceInboundWithRouter(t, &testRouter{})
}

func newSpecialServiceInboundWithRouter(t *testing.T, router adapter.Router) *Inbound {
	t.Helper()
	logFactory, err := log.New(log.Options{Options: option.LogOptions{Level: "debug"}})
	if err != nil {
		t.Fatal(err)
	}
	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal(err)
	}
	return &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeCloudflared, "test"),
		router:        router,
		logger:        logFactory.NewLogger("test"),
		configManager: configManager,
		flowLimiter:   &FlowLimiter{},
	}
}

type countingRouter struct {
	testRouter
	count atomic.Int32
}

func (r *countingRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	r.count.Add(1)
	r.testRouter.RouteConnectionEx(ctx, conn, metadata, onClose)
}

func startEchoListener(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
	return listener
}

func newSocksProxyService(t *testing.T, rules []IPRule) ResolvedService {
	t.Helper()
	service, err := parseResolvedService("socks-proxy", OriginRequestConfig{IPRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func newSocksProxyConnectRequest() *ConnectRequest {
	return &ConnectRequest{
		Type: ConnectionTypeWebsocket,
		Metadata: []Metadata{
			{Key: metadataHTTPHeader + ":Sec-WebSocket-Key", Val: "dGhlIHNhbXBsZSBub25jZQ=="},
		},
	}
}

func startSocksProxyStream(t *testing.T, inboundInstance *Inbound, service ResolvedService) (net.Conn, <-chan struct{}) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	respWriter := &fakeConnectResponseWriter{done: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		inboundInstance.handleSocksProxyStream(context.Background(), serverSide, respWriter, newSocksProxyConnectRequest(), adapter.InboundContext{}, service)
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
	return clientSide, done
}

func writeSocksAuth(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, []byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string([]byte{5, 0}) {
		t.Fatalf("unexpected auth response: %v", data)
	}
}

func writeSocksConnectIPv4(t *testing.T, conn net.Conn, address string) []byte {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes := []byte{5, 1, 0, 1}
	requestBytes = append(requestBytes, net.ParseIP(host).To4()...)
	requestBytes = append(requestBytes, byte(port>>8), byte(port))
	if err := wsutil.WriteClientMessage(conn, ws.OpBinary, requestBytes); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(conn)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestHandleBastionStream(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

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
		inboundInstance.handleBastionStream(context.Background(), serverSide, respWriter, request, adapter.InboundContext{}, ResolvedService{})
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
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := newSocksProxyService(t, []IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{port},
		Allow:  true,
	}})

	clientSide, done := startSocksProxyStream(t, newSpecialServiceInbound(t), service)
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != 0 {
		t.Fatalf("unexpected connect response: %v", data)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(clientSide)
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

func TestHandleSocksProxyStreamDenyRule(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := newSocksProxyService(t, []IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{port},
		Allow:  false,
	}})
	router := &countingRouter{}
	clientSide, done := startSocksProxyStream(t, newSpecialServiceInboundWithRouter(t, router), service)
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplyRuleFailure {
		t.Fatalf("unexpected deny response: %v", data)
	}
	if router.count.Load() != 0 {
		t.Fatalf("expected no router dial, got %d", router.count.Load())
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleSocksProxyStreamPortMismatchDefaultDeny(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	service := newSocksProxyService(t, []IPRule{{
		Prefix: "127.0.0.0/8",
		Ports:  []int{port + 1},
		Allow:  true,
	}})
	router := &countingRouter{}
	clientSide, done := startSocksProxyStream(t, newSpecialServiceInboundWithRouter(t, router), service)
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplyRuleFailure {
		t.Fatalf("unexpected port mismatch response: %v", data)
	}
	if router.count.Load() != 0 {
		t.Fatalf("expected no router dial, got %d", router.count.Load())
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleSocksProxyStreamEmptyRulesDefaultDeny(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

	router := &countingRouter{}
	clientSide, done := startSocksProxyStream(t, newSpecialServiceInboundWithRouter(t, router), newSocksProxyService(t, nil))
	defer clientSide.Close()

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplyRuleFailure {
		t.Fatalf("unexpected empty-rule response: %v", data)
	}
	if router.count.Load() != 0 {
		t.Fatalf("expected no router dial, got %d", router.count.Load())
	}
	_ = clientSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("socks-proxy stream did not exit")
	}
}

func TestHandleSocksProxyStreamRuleOrderFirstMatchWins(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	allowFirst := newSocksProxyService(t, []IPRule{
		{Prefix: "127.0.0.0/8", Ports: []int{port}, Allow: true},
		{Prefix: "127.0.0.1/32", Ports: []int{port}, Allow: false},
	})
	denyFirst := newSocksProxyService(t, []IPRule{
		{Prefix: "127.0.0.1/32", Ports: []int{port}, Allow: false},
		{Prefix: "127.0.0.0/8", Ports: []int{port}, Allow: true},
	})

	t.Run("allow-first", func(t *testing.T) {
		clientSide, done := startSocksProxyStream(t, newSpecialServiceInbound(t), allowFirst)
		defer clientSide.Close()

		writeSocksAuth(t, clientSide)
		data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
		if len(data) != 10 || data[1] != socksReplySuccess {
			t.Fatalf("unexpected allow-first response: %v", data)
		}
		_ = clientSide.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("socks-proxy stream did not exit")
		}
	})

	t.Run("deny-first", func(t *testing.T) {
		router := &countingRouter{}
		clientSide, done := startSocksProxyStream(t, newSpecialServiceInboundWithRouter(t, router), denyFirst)
		defer clientSide.Close()

		writeSocksAuth(t, clientSide)
		data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
		if len(data) != 10 || data[1] != socksReplyRuleFailure {
			t.Fatalf("unexpected deny-first response: %v", data)
		}
		if router.count.Load() != 0 {
			t.Fatalf("expected no router dial, got %d", router.count.Load())
		}
		_ = clientSide.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("socks-proxy stream did not exit")
		}
	})
}

func TestHandleStreamService(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

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
		inboundInstance.handleStreamService(context.Background(), serverSide, respWriter, request, adapter.InboundContext{}, ResolvedService{
			Kind:        ResolvedServiceStream,
			Destination: M.ParseSocksaddr(listener.Addr().String()),
		})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream service connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
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
		t.Fatal("stream service did not exit")
	}
}

func TestHandleStreamServiceProxyTypeSocks(t *testing.T) {
	listener := startEchoListener(t)
	defer listener.Close()

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
		inboundInstance.handleStreamService(context.Background(), serverSide, respWriter, request, adapter.InboundContext{}, ResolvedService{
			Kind:        ResolvedServiceStream,
			Destination: M.ParseSocksaddr(listener.Addr().String()),
			OriginRequest: OriginRequestConfig{
				ProxyType: "socks",
			},
		})
	}()

	select {
	case <-respWriter.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for stream service connect response")
	}
	if respWriter.err != nil {
		t.Fatal(respWriter.err)
	}
	if respWriter.status != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 response, got %d", respWriter.status)
	}

	writeSocksAuth(t, clientSide)
	data := writeSocksConnectIPv4(t, clientSide, listener.Addr().String())
	if len(data) != 10 || data[1] != socksReplySuccess {
		t.Fatalf("unexpected socks connect response: %v", data)
	}

	if err := wsutil.WriteClientMessage(clientSide, ws.OpBinary, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	data, _, err := wsutil.ReadServerData(clientSide)
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
		t.Fatal("socks stream service did not exit")
	}
}
