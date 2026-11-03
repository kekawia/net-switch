package flows

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/AyoubAchour/net-switch/internal/engine/flowapi"
	"github.com/AyoubAchour/net-switch/internal/engine/platform"
	"github.com/AyoubAchour/net-switch/internal/engine/policy"
)

func revision(n uint64) policy.Revision {
	c := policy.Config{Lines: []platform.Line{{ID: "A"}, {ID: "B"}}, Lanes: map[string]string{"A": "A", "B": "B"}, AppLines: map[string]string{"pinned": "B"}, Combine: true, Shares: map[string]uint64{"A": 1, "B": 1}, IPv6: true}
	return policy.Revision{N: n, Hash: policy.Hash(c), Config: c}
}

var tuple = platform.Tuple{Source: netip.MustParseAddrPort("198.18.0.2:40000"), Destination: netip.MustParseAddrPort("203.0.113.7:443")}

func table(t *testing.T, l Limits) *Table {
	t.Helper()
	f := New(l, nil)
	if _, err := f.Apply(revision(1)); err != nil {
		t.Fatal(err)
	}
	return f
}
func admit(t *testing.T, f *Table, proto, app string) flowapi.Ticket {
	t.Helper()
	x, err := f.Begin(proto, tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x.Resolve(platform.Owner{AppID: app}); err != nil {
		t.Fatal(err)
	}
	return x
}

func TestRevisionsLanesAndClosedTotals(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "pinned")
	x.Add(10, 20)
	r := revision(2)
	r.Config.Lanes["B"] = "A"
	r.Hash = policy.Hash(r.Config)
	a, err := f.Apply(r)
	if err != nil {
		t.Fatal(err)
	}
	y := admit(t, f, "tcp", "pinned")
	p, err := f.Page("")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Flows) != 2 || p.Flows[0].Line != "B" || p.Flows[1].Line != "A" || p.Flows[0].Revision != 1 || p.Flows[1].Revision != 2 {
		t.Fatal("open flow moved", p)
	}
	x.SetCancel(func() { x.Close() })
	y.SetCancel(func() { y.Close() })
	result, err := f.CloseFlows(Selector{App: "pinned", NotLine: "A"}, a.Point)
	if err != nil || result.Closed != 1 {
		t.Fatal(result, err)
	}
	if f.Totals().Apps["pinned"] != (Bytes{10, 20}) {
		t.Fatal("closed bytes lost")
	}
	if f.Stats().Flows != 1 {
		t.Fatal("new flow closed")
	}
	y.Close()
	if f.Stats().TCPBytes != 0 || f.Stats().Handshakes != 0 {
		t.Fatal("reservation leaked")
	}
	if _, err := f.Apply(revision(1)); err != ErrStale {
		t.Fatal(err)
	}
	same, err := f.Apply(r)
	if err != nil || same != a {
		t.Fatal("idempotent apply changed point")
	}
	r.Config.Combine = false
	r.Hash = policy.Hash(r.Config)
	if _, err := f.Apply(r); err != ErrConflict {
		t.Fatal(err)
	}
}
func TestRejectedAndPredictDoNotAdvance(t *testing.T) {
	f := table(t, Defaults())
	r := revision(2)
	r.Config.Blocked = []string{"B"}
	delete(r.Config.Shares, "B")
	r.Hash = policy.Hash(r.Config)
	f.Apply(r)
	x, _ := f.Begin("tcp", tuple)
	if _, err := x.Resolve(platform.Owner{AppID: "pinned"}); err == nil {
		t.Fatal("blocked admitted")
	}
	x.Close()
	for range 100 {
		f.Predict("unknown")
	}
	if f.k.Load() != 0 {
		t.Fatal("rejection/predict advanced sequence")
	}
	y := admit(t, f, "udp", "")
	defer y.Close()
	if f.k.Load() != 1 {
		t.Fatal("admission did not advance once")
	}
	y.Resolve(platform.Owner{})
	if f.k.Load() != 1 {
		t.Fatal("repeat advanced")
	}
}

func TestEveryAdmissionLimit(t *testing.T) {
	for _, name := range []string{"flows", "handshakes", "udp", "perApp", "udpPerApp", "unknown", "unknownUDP"} {
		t.Run(name, func(t *testing.T) {
			l := Defaults()
			proto, app := "tcp", "known"
			switch name {
			case "flows":
				l.Flows = 1
			case "handshakes":
				l.Handshakes = 1
			case "udp":
				l.UDP = 1
				proto = "udp"
			case "perApp":
				l.PerApp = 1
			case "udpPerApp":
				l.UDPPerApp = 1
				proto = "udp"
			case "unknown":
				l.Unknown = 1
				app = ""
			case "unknownUDP":
				l.UnknownUDP = 1
				proto = "udp"
				app = ""
			}
			f := table(t, l)
			x := admit(t, f, proto, app)
			defer x.Close()
			y, err := f.Begin(proto, tuple)
			if err == nil {
				_, err = y.Resolve(platform.Owner{AppID: app})
				y.Close()
			}
			if err != ErrBudget {
				t.Fatalf("%s overflow accepted: %v", name, err)
			}
		})
	}
}
func TestPendingAndSnapshotBudgets(t *testing.T) {
	l := Defaults()
	l.PendingBytes = 10
	l.SnapshotBytes = 1
	f := table(t, l)
	if !f.ReservePending(10) || f.ReservePending(1) {
		t.Fatal("pending byte cap")
	}
	f.ReleasePending(10)
	x := admit(t, f, "udp", "known")
	defer x.Close()
	if _, err := f.Page(""); err != ErrBudget {
		t.Fatal("snapshot byte cap")
	}
}
func TestSnapshotPaginationExpiryAndLimits(t *testing.T) {
	l := Defaults()
	f := table(t, l)
	var tickets []flowapi.Ticket
	for range 130 {
		tickets = append(tickets, admit(t, f, "udp", "known"))
	}
	defer func() {
		for _, x := range tickets {
			x.Close()
		}
	}()
	var first Page
	for range 4 {
		p, err := f.Page("")
		if err != nil {
			t.Fatal(err)
		}
		first = p
	}
	if _, err := f.Page(""); err != ErrBudget {
		t.Fatal("snapshot count limit")
	}
	seen := len(first.Flows)
	cursor := first.Cursor
	for cursor != "" {
		p, err := f.Page(cursor)
		if err != nil {
			t.Fatal(err)
		}
		seen += len(p.Flows)
		cursor = p.Cursor
	}
	if seen != 130 {
		t.Fatal("pagination lost entries")
	}
	f.now = func() time.Time { return time.Now().Add(11 * time.Second) }
	if _, err := f.Page(first.Cursor); err == nil {
		t.Fatal("expired cursor accepted")
	}
	if f.Stats().SnapshotBytes != 0 {
		t.Fatal("snapshot bytes leaked")
	}
}
func TestTwentyThousandUDPSessions(t *testing.T) {
	f := table(t, Defaults())
	var tickets []flowapi.Ticket
	for range 20000 {
		x, err := f.Begin("udp", tuple)
		if err == nil {
			tickets = append(tickets, x)
		} else if err != ErrBudget {
			t.Fatal(err)
		}
	}
	if len(tickets) != 16384 {
		t.Fatal(len(tickets))
	}
	for _, x := range tickets {
		x.Close()
	}
}
func TestRejectionNoticeLimits(t *testing.T) {
	f := table(t, Defaults())
	fixed := time.Now()
	f.now = func() time.Time { return fixed }
	for range 1000 {
		if !f.AllowReject("a") {
			t.Fatal("early app limit")
		}
	}
	if f.AllowReject("a") {
		t.Fatal("app limit")
	}
	for _, app := range []string{"b", "c", "d", "e"} {
		for range 1000 {
			if !f.AllowReject(app) {
				t.Fatal("early global limit")
			}
		}
	}
	if f.AllowReject("f") {
		t.Fatal("global limit")
	}
}

func TestUnknownAdmissionCountersSurviveClosureAndExcludeRefusals(t *testing.T) {
	l := Defaults()
	l.Unknown = 3
	l.UnknownUDP = 1
	f := table(t, l)
	var held []flowapi.Ticket
	held = append(held, admit(t, f, "tcp", ""), admit(t, f, "udp", ""), admit(t, f, "tcp", ""), admit(t, f, "tcp", "known"))
	refused, err := f.Begin("udp", tuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := refused.Resolve(platform.Owner{}); err != ErrBudget {
		t.Fatalf("expected unknown budget refusal: %v", err)
	}
	refused.Close()
	before := f.Stats()
	if before.Admitted != 4 || before.AdmittedUnknown != 3 || before.AdmittedUnknownUDP != 1 || before.PeakUnknown != 3 || before.PeakUnknownUDP != 1 {
		t.Fatalf("admission counters: %+v", before)
	}
	for _, ticket := range held {
		ticket.Close()
	}
	after := f.Stats()
	if after.Unknown != 0 || after.UnknownUDP != 0 || after.AdmittedUnknown != 3 || after.AdmittedUnknownUDP != 1 || after.PeakUnknown != 3 {
		t.Fatalf("closure erased lifetime evidence: %+v", after)
	}
}

func TestUnattributedRefusalsShareOnlyTheGlobalBudget(t *testing.T) {
	f := table(t, Defaults())
	fixed := time.Now()
	f.now = func() time.Time { return fixed }
	for range 1000 {
		if !f.AllowReject("known") {
			t.Fatal("early known app limit")
		}
	}
	if f.AllowReject("known") {
		t.Fatal("known app exceeded its own limit")
	}
	for range 4000 {
		if !f.AllowReject("") {
			t.Fatal("unattributed apps were collapsed into one app bucket")
		}
	}
	if f.AllowReject("") || f.AllowReject("another") {
		t.Fatal("global limit was exceeded")
	}
	if f.Stats().DroppedNotices != 3 {
		t.Fatal("dropped notices weren't counted")
	}
}

type failStore struct{}

func (failStore) SaveApplied(policy.Applied) error { return errors.New("fsync failed") }
func TestPersistenceFailureNotApplied(t *testing.T) {
	f := New(Defaults(), failStore{})
	if _, err := f.Apply(revision(1)); err == nil || f.Applied() != nil {
		t.Fatal("failed save applied")
	}
}
func TestCancellationBeforeRegistration(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "known")
	f.CloseAll()
	ctx, cancel := context.WithCancel(context.Background())
	x.SetCancel(cancel)
	if ctx.Err() == nil {
		t.Fatal("late cancel registration lost")
	}
	x.Close()
}

func TestSharedReconnectKeepsRoutedFlows(t *testing.T) {
	f := table(t, Defaults())
	x := admit(t, f, "tcp", "shared")
	defer x.Close()
	if _, err := f.CloseFlows(Selector{App: "shared", NotLine: "A"}, 0); err == nil {
		t.Fatal("shared routed flows were reconnectable")
	}
	if f.Stats().Flows != 1 {
		t.Fatal("shared flow closed")
	}
}

func stormTuple(port int) platform.Tuple {
	addr := netip.AddrFrom4([4]byte{198, 18, byte((port >> 16) & 0xff), byte(((port >> 8) & 0xfe) | 2)})
	return platform.Tuple{
		Source:      netip.AddrPortFrom(addr, uint16(10000+(port%50000))),
		Destination: netip.MustParseAddrPort("203.0.113.7:443"),
	}
}

func TestSplitCohortTCPRefusalNeverStarvesLateRetransmits(t *testing.T) {
	for _, tc := range []struct {
		name           string
		earlyWorkers   int
		lateWorkers    int
		lateOffsetMS   int
		totalOfferings int
	}{
		{name: "185_early_115_late", earlyWorkers: 185, lateWorkers: 115, lateOffsetMS: 780, totalOfferings: 3808},
		{name: "299_early_1_late", earlyWorkers: 299, lateWorkers: 1, lateOffsetMS: 850, totalOfferings: 3808},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := table(t, Defaults())
			base := time.Unix(1_700_000_000, 0)
			now := base
			f.now = func() time.Time { return now }

			type worker struct {
				wakeAt  time.Time
				started time.Time
				tuple   platform.Tuple
				active  bool
			}
			workers := make([]worker, tc.earlyWorkers+tc.lateWorkers)
			nextPort := 1
			remaining := tc.totalOfferings
			openAttempt := func(w *worker, at time.Time) {
				if remaining == 0 {
					w.active = false
					return
				}
				remaining--
				w.tuple = stormTuple(nextPort)
				nextPort++
				w.started = at
				w.wakeAt = at
				w.active = true
			}
			for i := range workers {
				at := base.Add(110 * time.Millisecond)
				if i >= tc.earlyWorkers {
					at = base.Add(time.Duration(tc.lateOffsetMS) * time.Millisecond)
				}
				openAttempt(&workers[i], at)
			}

			perSecond := map[int64]int{}
			var maxRefusal time.Duration
			completed := 0
			for completed < tc.totalOfferings {
				best := -1
				for i := range workers {
					if !workers[i].active {
						continue
					}
					if best == -1 || workers[i].wakeAt.Before(workers[best].wakeAt) {
						best = i
					}
				}
				if best == -1 {
					t.Fatalf("deadlock after %d of %d refusals", completed, tc.totalOfferings)
				}
				w := &workers[best]
				now = w.wakeAt
				if f.AllowRejectTuple("bravo", w.tuple) {
					perSecond[now.Unix()]++
					if d := now.Sub(w.started); d > maxRefusal {
						maxRefusal = d
					}
					completed++
					openAttempt(w, now.Add(time.Millisecond))
				} else {
					w.wakeAt = now.Add(1020 * time.Millisecond)
				}
			}
			if maxRefusal > 1050*time.Millisecond {
				t.Fatalf("slowest refusal %v exceeded first-retransmit bound", maxRefusal)
			}
			for sec, count := range perSecond {
				if count > rejectPerAppPerSec {
					t.Fatalf("second %d emitted %d notices, want <= %d", sec, count, rejectPerAppPerSec)
				}
			}
			if len(f.rejectWaiting) != 0 || len(f.rejectWaitingApps) != 0 || f.rejectPriorGlobal != 0 || len(f.rejectPriorApps) != 0 {
				t.Fatalf("waiting state leaked after storm: waiting=%d apps=%v priorGlobal=%d priorApps=%v", len(f.rejectWaiting), f.rejectWaitingApps, f.rejectPriorGlobal, f.rejectPriorApps)
			}
		})
	}
}

func TestTupleRejectBoundaryGraceExpiryAndAdmissionCleanup(t *testing.T) {
	f := table(t, Defaults())
	s0 := time.Unix(1_700_000_100, 0)
	now := s0.Add(990 * time.Millisecond)
	f.now = func() time.Time { return now }

	// Exhaust S0's per-app budget and drop one late TCP tuple at S0+990ms.
	for range rejectPerAppPerSec {
		if !f.AllowReject("bravo") {
			t.Fatal("early S0 per-app limit")
		}
	}
	late := stormTuple(1)
	if f.AllowRejectTuple("bravo", late) {
		t.Fatal("expected S0+990ms tuple to drop")
	}

	// Cross two Unix-second boundaries to S2+10ms (1.02s linear SYN RTO):
	// non-waiting traffic stops at 999, holding 1 token for late's retransmit.
	now = s0.Add(2*time.Second + 10*time.Millisecond)
	for i := range rejectPerAppPerSec - 1 {
		if !f.AllowReject("bravo") {
			t.Fatalf("S2 non-waiting call %d failed early", i)
		}
	}
	if f.AllowReject("bravo") {
		t.Fatal("S2 non-waiting traffic consumed late tuple's reserved token")
	}
	if !f.AllowRejectTuple("bravo", late) {
		t.Fatal("S2+10ms boundary-crossing retransmit was starved")
	}
	if f.AllowReject("bravo") {
		t.Fatal("S2 exceeded hard 1,000/s per-app limit")
	}

	// Synthetic non-retransmitting flood in S2 caps reservations at 500 per app
	// (leaving >=500 tokens for brand-new SYNs in S3) and expires after 1.5s.
	for i := range 2000 {
		if f.AllowRejectTuple("bravo", stormTuple(100+i)) {
			t.Fatal("S2 flood unexpectedly allowed")
		}
	}
	if len(f.rejectWaiting) != rejectReservePerApp {
		t.Fatalf("waiting count = %d, want %d", len(f.rejectWaiting), rejectReservePerApp)
	}
	now = s0.Add(3*time.Second + 100*time.Millisecond)
	allowedNew := 0
	for range rejectPerAppPerSec {
		if f.AllowReject("bravo") {
			allowedNew++
		}
	}
	if allowedNew != rejectPerAppPerSec-rejectReservePerApp {
		t.Fatalf("S3 brand-new headroom = %d, want %d", allowedNew, rejectPerAppPerSec-rejectReservePerApp)
	}
	// Advance past S2+10ms + 1.5s = S3+510ms within the same S3 Unix second:
	// sweepRejectWaitingLocked frees all 500 abandoned reservations immediately.
	now = s0.Add(3*time.Second + 600*time.Millisecond)
	freed := 0
	for range rejectPerAppPerSec {
		if f.AllowReject("bravo") {
			freed++
		}
	}
	if freed != rejectReservePerApp {
		t.Fatalf("post-expiry freed headroom in S3 = %d, want %d", freed, rejectReservePerApp)
	}

	// Admitting a waiting TCP tuple clears its reservation immediately.
	admittedTuple := stormTuple(9999)
	if f.AllowRejectTuple("bravo", admittedTuple) {
		t.Fatal("expected S3 exhausted drop")
	}
	now = s0.Add(4*time.Second + 50*time.Millisecond)
	tk, err := f.Begin("tcp", admittedTuple)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tk.Resolve(platform.Owner{AppID: "bravo"}); err != nil {
		t.Fatal(err)
	}
	defer tk.Close()
	for i := range rejectPerAppPerSec {
		if !f.AllowReject("bravo") {
			t.Fatalf("admitted tuple leaked reservation at %d", i)
		}
	}
}
