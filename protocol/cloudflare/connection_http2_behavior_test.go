//go:build with_cloudflared

package cloudflare

import (
	"io"
	"net/http"
	"testing"

	"github.com/sagernet/sing-box/log"
)

type captureHTTP2Writer struct {
	header     http.Header
	flushCount int
	statusCode int
	body       []byte
	panicWrite bool
}

func (w *captureHTTP2Writer) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *captureHTTP2Writer) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *captureHTTP2Writer) Write(p []byte) (int, error) {
	if w.panicWrite {
		panic("write after close")
	}
	w.body = append(w.body, p...)
	return len(p), nil
}

func (w *captureHTTP2Writer) Flush() {
	w.flushCount++
}

func TestHTTP2NonStreamingResponseDoesNotFlush(t *testing.T) {
	writer := &captureHTTP2Writer{}
	flushState := &http2FlushState{}
	respWriter := &http2ResponseWriter{
		writer:     writer,
		flusher:    writer,
		flushState: flushState,
	}

	err := respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusOK, http.Header{
		"Content-Type":   []string{"application/json"},
		"Content-Length": []string{"2"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if writer.flushCount != 0 {
		t.Fatalf("expected no header flush for non-streaming response, got %d", writer.flushCount)
	}

	stream := &http2DataStream{
		writer:  writer,
		flusher: writer,
		state:   flushState,
		logger:  log.NewNOPFactory().NewLogger("test"),
	}
	if _, err := stream.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if writer.flushCount != 0 {
		t.Fatalf("expected no body flush for non-streaming response, got %d", writer.flushCount)
	}
}

func TestHTTP2StreamingResponsesFlush(t *testing.T) {
	testCases := []struct {
		name   string
		header http.Header
	}{
		{
			name: "sse",
			header: http.Header{
				"Content-Type":   []string{"text/event-stream"},
				"Content-Length": []string{"1"},
			},
		},
		{
			name: "grpc",
			header: http.Header{
				"Content-Type":   []string{"application/grpc"},
				"Content-Length": []string{"1"},
			},
		},
		{
			name: "ndjson",
			header: http.Header{
				"Content-Type":   []string{"application/x-ndjson"},
				"Content-Length": []string{"1"},
			},
		},
		{
			name: "chunked",
			header: http.Header{
				"Content-Type":      []string{"application/json"},
				"Content-Length":    []string{"-1"},
				"Transfer-Encoding": []string{"chunked"},
			},
		},
		{
			name: "no-content-length",
			header: http.Header{
				"Content-Type": []string{"application/json"},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			writer := &captureHTTP2Writer{}
			flushState := &http2FlushState{}
			respWriter := &http2ResponseWriter{
				writer:     writer,
				flusher:    writer,
				flushState: flushState,
			}

			err := respWriter.WriteResponse(nil, encodeResponseHeaders(http.StatusOK, testCase.header))
			if err != nil {
				t.Fatal(err)
			}
			if writer.flushCount == 0 {
				t.Fatal("expected header flush for streaming response")
			}

			stream := &http2DataStream{
				writer:  writer,
				flusher: writer,
				state:   flushState,
				logger:  log.NewNOPFactory().NewLogger("test"),
			}
			if _, err := stream.Write([]byte("chunk")); err != nil {
				t.Fatal(err)
			}
			if writer.flushCount < 2 {
				t.Fatalf("expected body flush for streaming response, got %d flushes", writer.flushCount)
			}
		})
	}
}

func TestHTTP2DataStreamWriteRecoversPanic(t *testing.T) {
	writer := &captureHTTP2Writer{panicWrite: true}
	stream := &http2DataStream{
		writer:  writer,
		flusher: writer,
		state:   &http2FlushState{shouldFlush: true},
		logger:  log.NewNOPFactory().NewLogger("test"),
	}

	_, err := stream.Write([]byte("panic"))
	if err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe, got %v", err)
	}
}
