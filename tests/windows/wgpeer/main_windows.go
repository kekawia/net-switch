//go:build windows

// Test-only userspace WireGuard peer for disposable GitHub-hosted Windows CI.
// Pairs with the official signed WireGuard for Windows MSI (WireGuardNT kernel
// tunnel) on the host without injecting self-sourced packets back into tcpip.sys.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type keypair struct {
	privHex string
	pubHex  string
	privB64 string
	pubB64  string
}

func generateKeypair() (keypair, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return keypair{}, err
	}
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	sk, err := ecdh.X25519().NewPrivateKey(raw[:])
	if err != nil {
		return keypair{}, err
	}
	pub := sk.PublicKey().Bytes()
	return keypair{
		privHex: hex.EncodeToString(raw[:]),
		pubHex:  hex.EncodeToString(pub),
		privB64: base64.StdEncoding.EncodeToString(raw[:]),
		pubB64:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}

func parseListenPort(ipc string) (int, error) {
	for _, line := range strings.Split(ipc, "\n") {
		if val, ok := strings.CutPrefix(strings.TrimSpace(line), "listen_port="); ok {
			p, err := strconv.Atoi(val)
			if err == nil && p > 0 {
				return p, nil
			}
		}
	}
	return 0, errors.New("listen_port missing from WireGuard IpcGet")
}

func main() {
	statePath := flag.String("state", "", "JSON state output path")
	flag.Parse()

	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		log.Fatal("wgpeer may run only on disposable GitHub-hosted Windows runners")
	}
	if *statePath == "" {
		log.Fatal("missing --state")
	}

	serverKey, err := generateKeypair()
	if err != nil {
		log.Fatalf("server keypair: %v", err)
	}
	clientKey, err := generateKeypair()
	if err != nil {
		log.Fatalf("client keypair: %v", err)
	}
	splitKey, err := generateKeypair()
	if err != nil {
		log.Fatalf("split keypair: %v", err)
	}

	localAddrs := []netip.Addr{
		netip.MustParseAddr("10.88.0.1"),
		netip.MustParseAddr("10.88.1.1"),
		netip.MustParseAddr("198.51.100.10"),
		netip.MustParseAddr("198.51.101.10"),
	}
	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, nil, 1420)
	if err != nil {
		log.Fatalf("CreateNetTUN: %v", err)
	}

	wgDev := device.NewDevice(tunDev, conn.NewStdNetBind(), device.NewLogger(device.LogLevelError, "wgpeer: "))
	defer wgDev.Close()

	uapi := fmt.Sprintf(
		"private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.88.0.2/32\npublic_key=%s\nallowed_ip=10.88.1.2/32\n",
		serverKey.privHex,
		clientKey.pubHex,
		splitKey.pubHex,
	)
	if err := wgDev.IpcSet(uapi); err != nil {
		log.Fatalf("IpcSet: %v", err)
	}
	if err := wgDev.Up(); err != nil {
		log.Fatalf("wgDev.Up: %v", err)
	}

	ipcState, err := wgDev.IpcGet()
	if err != nil {
		log.Fatalf("IpcGet: %v", err)
	}
	listenPort, err := parseListenPort(ipcState)
	if err != nil {
		log.Fatalf("parseListenPort: %v", err)
	}

	var tcpMainHits atomic.Uint64
	var tcpSplitHits atomic.Uint64
	var udpHits atomic.Uint64

	serveHTTP := func(addr string, via string, counter *atomic.Uint64) *http.Server {
		ln, err := tnet.ListenTCPAddrPort(netip.MustParseAddrPort(addr))
		if err != nil {
			log.Fatalf("ListenTCPAddrPort(%s): %v", addr, err)
		}
		srv := &http.Server{
			ReadHeaderTimeout: 5 * time.Second,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seq := counter.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Connection", "close")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"via":    via,
					"target": addr,
					"source": r.RemoteAddr,
					"nonce":  r.URL.Query().Get("nonce"),
					"seq":    seq,
				})
			}),
		}
		go func() { _ = srv.Serve(ln) }()
		return srv
	}

	mainHTTP := serveHTTP("198.51.100.10:8080", "wgpeer-include", &tcpMainHits)
	defer mainHTTP.Close()
	splitHTTP := serveHTTP("198.51.101.10:8080", "wgpeer-split", &tcpSplitHits)
	defer splitHTTP.Close()

	udpConn, err := tnet.ListenUDPAddrPort(netip.MustParseAddrPort("198.51.100.10:8081"))
	if err != nil {
		log.Fatalf("ListenUDPAddrPort: %v", err)
	}
	defer udpConn.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			udpHits.Add(1)
			reply := append([]byte("wgpeer-udp:"), buf[:n]...)
			_, _ = udpConn.WriteTo(reply, peer)
		}
	}()

	ctrlLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("control listen: %v", err)
	}
	defer ctrlLn.Close()

	done := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		ipc, _ := wgDev.IpcGet()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tcpMainHits":  tcpMainHits.Load(),
			"tcpSplitHits": tcpSplitHits.Load(),
			"udpHits":      udpHits.Load(),
			"ipc":          ipc,
		})
	})
	mux.HandleFunc("/stop", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
		select {
		case <-done:
		default:
			close(done)
		}
	})
	ctrlSrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = ctrlSrv.Serve(ctrlLn) }()
	defer ctrlSrv.Close()

	readyPayload, err := json.MarshalIndent(map[string]any{
		"listenPort":            listenPort,
		"control":               "http://" + ctrlLn.Addr().String(),
		"serverPublicKeyBase64": serverKey.pubB64,
		"clientPrivateKeyBase64": clientKey.privB64,
		"splitPrivateKeyBase64": splitKey.privB64,
		"includeHTTP":           "http://198.51.100.10:8080",
		"includeUDP":            "198.51.100.10:8081",
		"splitHTTP":             "http://198.51.101.10:8080",
	}, "", "  ")
	if err != nil {
		log.Fatalf("marshal state: %v", err)
	}
	tmp := *statePath + ".tmp"
	if err := os.WriteFile(tmp, readyPayload, 0o600); err != nil {
		log.Fatalf("write state tmp: %v", err)
	}
	if err := os.Rename(tmp, *statePath); err != nil {
		log.Fatalf("rename state: %v", err)
	}

	<-done
}
