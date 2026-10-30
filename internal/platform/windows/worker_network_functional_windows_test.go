package winplatform

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/control/engine"
	"github.com/AyoubAchour/net-switch/internal/platform/worker"
	"golang.org/x/sys/windows"
)

// Only linked into the hosted test binary. Trust one generated certificate
// without editing a machine certificate store or disabling TLS verification.
func installWorkerTestRoots() {
	value := os.Getenv("NETSWITCH_TEST_ROOT_CERT")
	if value == "" {
		return
	}
	der, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	x509.SetFallbackRoots(pool)
}

func TestWorkerNetworkOperations(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Skip("requires disposable hosted Windows")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("NETSWITCH_EXPECT_SYSTEM") == "1" && user.User.Sid.String() != "S-1-5-18" {
		t.Fatal("not SYSTEM")
	}
	t.Logf("network operation parent SID=%s", user.User.Sid.String())
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var ip net.IP
	var index int
	var alias string
	for _, nic := range interfaces {
		addresses, err := nic.Addrs()
		if err != nil {
			t.Fatal(err)
		}
		for _, address := range addresses {
			candidate, _, err := net.ParseCIDR(address.String())
			if err == nil && candidate.To4() != nil && !candidate.IsLoopback() && !candidate.IsLinkLocalUnicast() {
				ip = candidate
				index = nic.Index
				alias = nic.Name
				break
			}
		}
		if ip != nil {
			break
		}
	}
	if ip == nil {
		t.Fatal("hosted qualification requires a real IPv4 adapter")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{ip}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	server.Listener.Close()
	server.Listener = listener
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	t.Setenv("NETSWITCH_TEST_ROOT_CERT", base64.StdEncoding.EncodeToString(der))
	originalDebug := os.Getenv("GODEBUG")
	t.Setenv("GODEBUG", strings.TrimPrefix(os.Getenv("GODEBUG")+",x509usefallbackroots=1", ","))
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s := worker.Supervisor{Executable: exe}
	t.Run("line-check-HTTPS-system-trust", func(t *testing.T) {
		// The local certificate fixture exercises validation, but deliberately
		// bypasses Windows' system verifier. Qualify that real path separately.
		t.Setenv("NETSWITCH_TEST_ROOT_CERT", "")
		t.Setenv("GODEBUG", originalDebug)
		const target = "1.1.1.1:443" // the product's existing Cloudflare full-check endpoint
		baseline := checkLine(uint32(index), target, false, false)
		if baseline.Outcome != engine.OK {
			t.Fatalf("external HTTPS positive control unavailable; cannot qualify system trust: %+v", baseline)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		value, err := s.Once(ctx, "line-check", map[string]any{"index": index, "target": target, "quick": false, "custom": false})
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var result engine.ProbeResult
		if err = json.Unmarshal(b, &result); err != nil || result.Outcome != engine.OK {
			t.Fatalf("system-trust worker HTTPS failed after parent success: %s %v", b, err)
		}
		t.Logf("system-trust HTTPS interface=%d target=%s result=%s", index, target, b)
	})
	t.Run("metrics", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		value, err := s.Once(ctx, "metrics", map[string]any{"alias": alias})
		if err != nil {
			t.Fatal(err)
		}
		rows, ok := value.([]any)
		if !ok || len(rows) == 0 {
			t.Fatalf("no interface metrics: %#v", value)
		}
		t.Logf("interface=%s metrics=%v", alias, rows)
	})
	for _, quick := range []bool{true, false} {
		t.Run(fmtNetworkCase(quick), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			value, err := s.Once(ctx, "line-check", map[string]any{"index": index, "target": listener.Addr().String(), "quick": quick, "custom": true})
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var result engine.ProbeResult
			if err := json.Unmarshal(b, &result); err != nil || result.Outcome != engine.OK {
				t.Fatalf("bound line check failed: %s %v", b, err)
			}
			t.Logf("bound interface=%d target=%s result=%s", index, listener.Addr(), b)
		})
	}
	t.Run("probe", func(t *testing.T) {
		p, err := worker.Start(exe, []string{"worker", "probe", "--interface-index", strconv.Itoa(index), "--targets", listener.Addr().String()})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		stop := context.AfterFunc(ctx, func() { _ = p.Kill() })
		defer stop()
		p.Input().Close()
		b, err := io.ReadAll(io.LimitReader(p.Output(), 65536))
		if waitErr := p.Wait(); err != nil || waitErr != nil {
			t.Fatalf("read=%v wait=%v", err, waitErr)
		}
		var result probeResult
		if err := json.Unmarshal(b, &result); err != nil || !result.OK {
			t.Fatalf("bound probe failed: %s %v", b, err)
		}
		t.Logf("bound probe=%s", b)
	})
}
func fmtNetworkCase(quick bool) string {
	if quick {
		return "line-check-TCP"
	}
	return "line-check-HTTPS-verified"
}
