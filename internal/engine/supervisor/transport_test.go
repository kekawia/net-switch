package supervisor

import (
	"bufio"
	"context"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayPreservesFinalFrameBeforeEOF(t *testing.T) {
	for _, want := range []string{"{\"id\":\"stop\",\"result\":true}\n", "{\"id\":\"stop\",\"error\":\"cleanup failed\"}\n"} {
		t.Run(want, func(t *testing.T) { testFinalFrame(t, want) })
	}
}

func testFinalFrame(t *testing.T, want string) {
	t.Helper()
	client, public := net.Pipe()
	private, engine := net.Pipe()
	defer client.Close()
	defer engine.Close()
	done := make(chan struct{})
	go func() { Relay(context.Background(), public, private); close(done) }()
	go func() { Write(engine, []byte(want)); engine.Close() }()
	client.SetReadDeadline(time.Now().Add(time.Second))
	got, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || got != want {
		t.Fatal(got, err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not join")
	}
}
func TestSlowRelayAndLogReaderCannotHoldPrivateCompletion(t *testing.T) {
	client, public := net.Pipe()
	private, engine := net.Pipe()
	defer client.Close()
	defer engine.Close()
	done := make(chan struct{})
	go func() { Relay(context.Background(), public, private); close(done) }()
	go func() {
		for range 10 {
			if Write(engine, []byte("{\"id\":\"bulk\"}\n")) != nil {
				return
			}
		}
	}()
	a, b := net.Pipe()
	c := NewChannel(a, a)
	defer c.Close()
	defer b.Close()
	go func() { Write(b, []byte("{\"kind\":\"complete\",\"code\":3}\n")); b.Close() }()
	select {
	case m := <-c.Messages():
		if m.Kind != "complete" || m.Code != 3 {
			t.Fatal(m)
		}
	case <-time.After(time.Second):
		t.Fatal("bulk relay blocked private completion")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("slow reader retained relay")
	}
	r, w := io.Pipe()
	logs := NewLog(w)
	defer r.Close()
	defer w.Close()
	for range 256 {
		logs.Write(make([]byte, 8192))
	}
	if logs.Dropped.Load() == 0 {
		t.Fatal("blocked sink did not exercise log bound")
	}
}
func TestPrivateCompletionIsDrainedAfterEOF(t *testing.T) {
	a, b := net.Pipe()
	c := NewChannel(a, a)
	defer c.Close()
	go func() { Write(b, []byte("{\"kind\":\"ready\"}\n{\"kind\":\"complete\",\"code\":3}\n")); b.Close() }()
	<-c.Done()
	var got []string
	for m := range c.Messages() {
		got = append(got, m.Kind)
	}
	if strings.Join(got, ",") != "ready,complete" {
		t.Fatal(got)
	}
}
func TestFrameLimitAndPartialFrame(t *testing.T) {
	for _, input := range []string{strings.Repeat("a", 4097) + "\n", "partial"} {
		if _, err := Line(bufio.NewReader(strings.NewReader(input)), 4096); err == nil {
			t.Fatal("accepted bad frame")
		}
	}
}

type gatedSink struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	mu      sync.Mutex
	records []string
}

func (g *gatedSink) Write(b []byte) (int, error) {
	g.once.Do(func() {
		close(g.entered)
		<-g.release
	})
	g.mu.Lock()
	g.records = append(g.records, string(b))
	g.mu.Unlock()
	return len(b), nil
}

func TestCriticalLogsSurviveBulkFloodAndFlushDrainsOrTimesOut(t *testing.T) {
	sink := &gatedSink{entered: make(chan struct{}), release: make(chan struct{})}
	logs := NewLog(sink)
	logs.Write([]byte("bulk-0"))
	<-sink.entered
	for range 512 {
		logs.Write([]byte("bulk-flood"))
	}
	if logs.Dropped.Load() == 0 {
		t.Fatal("bulk flood did not exercise 64-slot queue drop")
	}
	for _, msg := range []string{"NATIVE_TERMINATE", "NATIVE_TERMINATED", "NATIVE_CLEANED"} {
		logs.WriteCritical([]byte(msg))
	}
	// While the sink is wedged, Flush must respect its context deadline promptly.
	wedgedCtx, cancelWedged := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelWedged()
	if logs.Flush(wedgedCtx) {
		t.Fatal("Flush reported idle while sink was still blocked")
	}
	close(sink.release)
	drainCtx, cancelDrain := context.WithTimeout(context.Background(), time.Second)
	defer cancelDrain()
	if !logs.Flush(drainCtx) {
		t.Fatal("Flush did not drain after sink unblocked")
	}
	sink.mu.Lock()
	got := slices.Clone(sink.records)
	sink.mu.Unlock()
	// After the in-progress bulk-0 write finishes, all three critical milestones
	// must drain ahead of the remaining 64 queued bulk-flood chunks.
	wantPrefix := []string{"bulk-0", "NATIVE_TERMINATE", "NATIVE_TERMINATED", "NATIVE_CLEANED"}
	if len(got) < len(wantPrefix) || !slices.Equal(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("critical milestones did not survive and preempt bulk flood: got prefix %v", got[:min(len(got), 8)])
	}
}
