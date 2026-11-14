package flows

import (
	"errors"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/proxy"
)

func TestLineErrorSkipsNonFaultProxyErrorsAndUnsupportedUDP(t *testing.T) {
	tbl := New(Defaults(), nil)

	// Destination and cap errors + ErrUnsupportedUDP must NOT emit lineError events.
	tbl.LineError("px1", &proxy.Error{Kind: proxy.KindDestination, Protocol: "socks5", Code: 0x05})
	tbl.LineError("px1", &proxy.Error{Kind: proxy.KindCapExceeded, Protocol: "http"})
	tbl.LineError("px1", platform.ErrUnsupportedUDP)
	select {
	case ev := <-tbl.Events():
		t.Fatalf("unexpected event for non-line-fault error: %+v", ev)
	default:
	}

	// Real proxy/carrier faults MUST emit lineError events.
	tbl.LineError("px1", &proxy.Error{Kind: proxy.KindAuth, Protocol: "socks5", Code: 0x01})
	select {
	case ev := <-tbl.Events():
		if ev.Type != "lineError" || ev.Line != "px1" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	default:
		t.Fatal("expected lineError event for proxy auth failure")
	}

	tbl.LineError("cable", errors.New("network unreachable"))
	select {
	case ev := <-tbl.Events():
		if ev.Type != "lineError" || ev.Line != "cable" {
			t.Fatalf("unexpected physical lineError event: %+v", ev)
		}
	default:
		t.Fatal("expected lineError event for physical dial error")
	}
}

func TestUnsupportedUDPCountersBoundedPerLineAndApp(t *testing.T) {
	tbl := New(Defaults(), nil)
	tbl.UnsupportedUDP("http-px", "browser", 3)
	tbl.UnsupportedUDP("http-px", "browser", 9)
	tbl.UnsupportedUDP("http-px", "game", 2)

	summary := tbl.UnsupportedUDPStats()
	if summary.Total != 14 || summary.Lines["http-px"] != 14 || summary.Apps["browser"] != 12 || summary.Apps["game"] != 2 {
		t.Fatalf("unexpected summary: %+v", summary)
	}
	if tbl.Stats().UnsupportedUDP != 14 {
		t.Fatalf("Stats().UnsupportedUDP = %d, want 14", tbl.Stats().UnsupportedUDP)
	}
}
