package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDownloadRetriesRejectedBody(t *testing.T) {
	good := []byte("the verified tool archive")
	sum := sha256.Sum256(good)
	for _, kind := range []string{"valid", "hash", "size", "interrupted"} {
		t.Run(kind, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					switch kind {
					case "valid":
						w.Write(good)
					case "hash":
						bad := bytes.Clone(good)
						bad[0] ^= 1
						w.Write(bad)
					case "size":
						w.Write(good[:len(good)-1])
					case "interrupted":
						w.Header().Set("Content-Length", strconv.Itoa(len(good)))
						w.Write(good[:len(good)/2])
					}
					return
				}
				w.Write(good)
			}))
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			pin := Pin{URL: server.URL, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(good))}
			data, err := Download(ctx, pin)
			t.Logf("%s: %d HTTP requests", kind, requests.Load())
			wantRequests := int32(2)
			if kind == "valid" {
				wantRequests = 1
			}
			if err != nil || !bytes.Equal(data, good) || requests.Load() != wantRequests {
				t.Fatalf("download: bytes=%q requests=%d want=%d error=%v", data, requests.Load(), wantRequests, err)
			}
		})
	}
}

func TestDownloadRejectsPersistentBody(t *testing.T) {
	good := []byte("the verified tool archive")
	sum := sha256.Sum256(good)
	bad := bytes.Clone(good)
	bad[0] ^= 1
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write(bad)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pin := Pin{URL: server.URL, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(good))}
	data, err := Download(ctx, pin)
	t.Logf("persistent mismatch: %d HTTP requests", requests.Load())
	if err == nil || !strings.Contains(err.Error(), "SHA-256") || len(data) != 0 || requests.Load() != 4 {
		t.Fatalf("persistent mismatch: bytes=%q requests=%d want=4 error=%v", data, requests.Load(), err)
	}
}

func TestVerify(t *testing.T) {
	data := []byte("appimage runtime payload")
	sum := sha256.Sum256(data)
	pin := Pin{URL: "https://example.invalid/runtime", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data))}
	if err := Verify(data, pin); err != nil {
		t.Fatal(err)
	}
	bad := pin
	bad.SHA256 = "00" + pin.SHA256[2:]
	if Verify(data, bad) == nil {
		t.Fatal("a different hash must be rejected")
	}
	short := pin
	short.Size++
	if Verify(data, short) == nil {
		t.Fatal("a different size must be rejected")
	}
}
