//go:build with_cloudflared

package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"

	"github.com/google/uuid"
)

func requireEnvVars(t *testing.T) (token string, testURL string) {
	t.Helper()
	token = os.Getenv("CF_TUNNEL_TOKEN")
	testURL = os.Getenv("CF_TEST_URL")
	if token == "" || testURL == "" {
		t.Skip("CF_TUNNEL_TOKEN and CF_TEST_URL must be set")
	}
	return
}

func startOriginServer(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.Copy(w, r.Body)
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		codeStr := strings.TrimPrefix(r.URL.Path, "/status/")
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			code = 200
		}
		w.Header().Set("X-Custom", "test-value")
		w.WriteHeader(code)
		fmt.Fprintf(w, "status: %d", code)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(r.Header)
	})

	server := &http.Server{
		Addr:    "127.0.0.1:8083",
		Handler: mux,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		t.Fatal("start origin server: ", err)
	}

	go server.Serve(listener)
	t.Cleanup(func() {
		server.Close()
	})
}

type testRouter struct {
	preMatch func(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error)
}

func (r *testRouter) Start(stage adapter.StartStage) error { return nil }

func (r *testRouter) Close() error { return nil }

func (r *testRouter) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	destination := metadata.Destination.String()
	upstream, err := net.Dial("tcp", destination)
	if err != nil {
		conn.Close()
		return err
	}
	go func() {
		io.Copy(upstream, conn)
		upstream.Close()
	}()
	io.Copy(conn, upstream)
	conn.Close()
	return nil
}

func (r *testRouter) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return nil
}

func (r *testRouter) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	destination := metadata.Destination.String()
	upstream, err := net.Dial("tcp", destination)
	if err != nil {
		conn.Close()
		onClose(err)
		return
	}
	var once sync.Once
	closeFn := func() {
		once.Do(func() {
			conn.Close()
			upstream.Close()
		})
	}
	go func() {
		io.Copy(upstream, conn)
		closeFn()
	}()
	io.Copy(conn, upstream)
	closeFn()
	onClose(nil)
}

func (r *testRouter) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	onClose(nil)
}

func (r *testRouter) DialRouteConnection(ctx context.Context, metadata adapter.InboundContext) (net.Conn, error) {
	return net.Dial("tcp", metadata.Destination.String())
}

func (r *testRouter) DialRoutePacketConnection(ctx context.Context, metadata adapter.InboundContext) (N.PacketConn, error) {
	conn, err := net.Dial("udp", metadata.Destination.String())
	if err != nil {
		return nil, err
	}
	return bufio.NewUnbindPacketConn(conn), nil
}

func (r *testRouter) PreMatch(metadata adapter.InboundContext, routeContext tun.DirectRouteContext, timeout time.Duration, supportBypass bool) (tun.DirectRouteDestination, error) {
	if r.preMatch != nil {
		return r.preMatch(metadata, routeContext, timeout, supportBypass)
	}
	return nil, nil
}

func (r *testRouter) RuleSet(tag string) (adapter.RuleSet, bool) { return nil, false }

func (r *testRouter) Rules() []adapter.Rule { return nil }

func (r *testRouter) NeedFindProcess() bool { return false }

func (r *testRouter) NeedFindNeighbor() bool { return false }

func (r *testRouter) NeighborResolver() adapter.NeighborResolver { return nil }

func (r *testRouter) AppendTracker(tracker adapter.ConnectionTracker) {}

func (r *testRouter) ResetNetwork() {}

func newTestInbound(t *testing.T, token string, protocol string, haConnections int) *Inbound {
	t.Helper()
	credentials, err := parseToken(token)
	if err != nil {
		t.Fatal("parse token: ", err)
	}

	logFactory, err := log.New(log.Options{Options: option.LogOptions{Level: "debug"}})
	if err != nil {
		t.Fatal("create logger: ", err)
	}

	configManager, err := NewConfigManager()
	if err != nil {
		t.Fatal("create config manager: ", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	inboundInstance := &Inbound{
		Adapter:           inbound.NewAdapter(C.TypeCloudflared, "test"),
		ctx:               ctx,
		cancel:            cancel,
		router:            &testRouter{},
		logger:            logFactory.NewLogger("test"),
		credentials:       credentials,
		connectorID:       uuid.New(),
		haConnections:     haConnections,
		protocol:          protocol,
		edgeIPVersion:     0,
		datagramVersion:   "",
		gracePeriod:       5 * time.Second,
		configManager:     configManager,
		datagramV2Muxers:  make(map[DatagramSender]*DatagramV2Muxer),
		datagramV3Muxers:  make(map[DatagramSender]*DatagramV3Muxer),
		datagramV3Manager: NewDatagramV3SessionManager(),
		controlDialer:     N.SystemDialer,
		accessCache:       &accessValidatorCache{values: make(map[string]accessValidator), dialer: N.SystemDialer},
	}

	t.Cleanup(func() {
		cancel()
		inboundInstance.Close()
	})
	return inboundInstance
}

func waitForTunnel(t *testing.T, testURL string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 5 * time.Second}
	var lastErr error
	var lastStatus int
	var lastBody string
	for time.Now().Before(deadline) {
		resp, err := client.Get(testURL + "/ping")
		if err != nil {
			lastErr = err
			time.Sleep(500 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		lastStatus = resp.StatusCode
		lastBody = string(body)
		if resp.StatusCode == http.StatusOK && lastBody == `{"ok":true}` {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("tunnel not ready after %s (lastErr=%v, lastStatus=%d, lastBody=%q)", timeout, lastErr, lastStatus, lastBody)
}
