package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kekawia/net-switch/internal/engine/protocol"
	"github.com/kekawia/net-switch/internal/localipc"
)

// The owner's `netswitchctl diagnostics` goes through Control's real request
// path and saves a report with the personal details replaced.
func TestDiagnosticsCommandSavesTheOwnersReport(t *testing.T) {
	data := t.TempDir()
	logLine := `2026-11-23T03:28:58Z reconnect c:\users\dana\appdata\app.exe: closed 1`
	if err := os.WriteFile(filepath.Join(data, "NetSwitch.log"), []byte(logLine+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Access{Owner: Owner{User: "owner-sid", Name: `PC-1\Dana`}, Tokens: NewTokens(), Desktop: &DesktopBridge{}, Remote: NewRemote(ctx, func(string) {}), Data: data}
	old := dialIPC
	t.Cleanup(func() { dialIPC = old })
	dialIPC = func(ctx context.Context, e localipc.Endpoint) (*localipc.Conn, error) {
		if e.Kind != "desktop" {
			t.Errorf("report asked on the %s endpoint", e.Kind)
		}
		client, server := net.Pipe()
		go a.serve(ctx, &localipc.Conn{ReadWriteCloser: server, Peer: localipc.Peer{User: "owner-sid"}}, false)
		return &localipc.Conn{ReadWriteCloser: client}, nil
	}
	out := filepath.Join(t.TempDir(), "report.txt")
	if err := DiagnosticsCommand(ctx, data, out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	report := string(b)
	for _, want := range []string{"Net Switch problem report", "Routing: off", `reconnect c:\users\[user-1]\appdata\app.exe: closed 1`} {
		if !strings.Contains(report, want) {
			t.Fatalf("report lacks %q:\n%s", want, report)
		}
	}
	if strings.Contains(strings.ToLower(report), "dana") {
		t.Fatal("the owner's name is in the report:\n" + report)
	}
}

func TestDiagnosticsIsOwnerOnly(t *testing.T) {
	a := &Access{Owner: Owner{User: "owner"}, Tokens: NewTokens(), Data: t.TempDir()}
	for _, peer := range []string{"stranger", ""} {
		if _, err := a.request(context.Background(), localipc.Peer{User: peer}, false, "c", controlRequest{Method: "diagnostics"}); err == nil {
			t.Fatalf("report given to %q", peer)
		}
	}
	if _, err := a.request(context.Background(), localipc.Peer{User: "owner"}, true, "c", controlRequest{Method: "diagnostics"}); err == nil {
		t.Fatal("report given on the status-only endpoint")
	}
}

// Without Control, only an administrator can read the protected logs; anyone
// else is told how to get them instead of seeing a bare connection error.
func TestDiagnosticsWithoutControlNamesTheWayOut(t *testing.T) {
	if Administrator() {
		t.Skip("this account reads the logs directly")
	}
	old := dialIPC
	t.Cleanup(func() { dialIPC = old })
	dialIPC = func(context.Context, localipc.Endpoint) (*localipc.Conn, error) {
		return nil, errors.New("the pipe is not there")
	}
	err := DiagnosticsCommand(context.Background(), t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), "Run this again as administrator") {
		t.Fatal("unhelpful error:", err)
	}
}

func TestShortenTimingsKeepsTotalsSlowestStepsAndErrors(t *testing.T) {
	prefix := "2026-11-23T02:03:52.4670384Z 2026/11/23 03:03:52 "
	line := prefix + `WINDOWS LIFECYCLE {"instance":"293c0295b33ba5e78339054d182655d2","operation":"stop","phases":{"cleanup.total":{"calls":1,"totalNanos":465548900,"maxNanos":465548900},"engine.start.total":{"calls":1,"totalNanos":4615902100,"maxNanos":4615902100},"route.fingerprint.inspect":{"calls":3225,"totalNanos":2603115600,"maxNanos":138882800},"adapter.create.api":{"calls":1,"totalNanos":2085131400,"maxNanos":2085131400},"tun.close.device":{"calls":1,"totalNanos":180720000,"maxNanos":180720000},"dns.inspect":{"calls":2,"totalNanos":2123100,"maxNanos":1818200}},"error":"adapter vanished"}`
	want := prefix + "WINDOWS LIFECYCLE instance=293c0295b33ba5e78339054d182655d2 operation=stop; totals: cleanup 466ms, engine.start 4.616s; slowest: route.fingerprint.inspect 2.603s (3225 calls), adapter.create.api 2.085s (1 call), tun.close.device 181ms (1 call); error: adapter vanished (full timings in the log)"
	if got := shortenTimings(line); got != want {
		t.Fatalf("\n got: %s\nwant: %s", got, want)
	}
	// The host's log sink cuts lines at 4 KiB, so most stop records end early.
	cut := prefix + `WINDOWS LIFECYCLE {"instance":"2d6937875d45ca8742af597c69044ba9","operation":"stop","phases":{"cleanup.total":{"calls":2,"totalNanos":257880200,"maxNanos":257635100},"route.fingerprint.inspect":{"calls":10950,"totalNanos":3473140600,"maxNanos":1175600},"tun.setup.total":{"calls":1,"totalN`
	want = prefix + "WINDOWS LIFECYCLE instance=2d6937875d45ca8742af597c69044ba9 operation=stop; totals: cleanup 258ms; slowest: route.fingerprint.inspect 3.473s (10950 calls) (record cut in the log)"
	if got := shortenTimings(cut); got != want {
		t.Fatalf("cut record\n got: %s\nwant: %s", got, want)
	}
	for _, other := range []string{prefix + "native startup: native-enter", prefix + `WINDOWS LIFECYCLE {"operation":"stop-wait","phase":"journal.read"}`, prefix + "WINDOWS LIFECYCLE {not json"} {
		if got := shortenTimings(other); got != other {
			t.Fatal("changed a line that is not a timing record:", got)
		}
	}
}

// A log of characters JSON escapes six bytes wide (< > &) still fits one IPC
// reply: at full budgets it would not (400 KB × 6), so the budgets must halve.
func TestProblemReportFitsOneReply(t *testing.T) {
	data := t.TempDir()
	heavy := strings.Repeat(`<>&`, 200)
	var b strings.Builder
	for b.Len() < 2<<20 {
		b.WriteString(heavy + "\n")
	}
	for _, name := range []string{"NetSwitch.log", "NetSwitchEngine.log", "netswitch-update.log"} {
		if err := os.WriteFile(filepath.Join(data, name), []byte(b.String()+"newest line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report := problemReport(data, Owner{}, nil, "a test")
	encoded, err := json.Marshal(map[string]any{"id": "1", "result": map[string]any{"report": report}})
	if err != nil || len(encoded) > protocol.MessageLimit {
		t.Fatalf("reply of %d bytes exceeds the %d-byte frame (%v)", len(encoded), protocol.MessageLimit, err)
	}
	if strings.Count(report, "newest line") != 3 {
		t.Fatal("the newest line of each log is missing")
	}
}
