package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/buildinfo"
	"github.com/kekawia/net-switch/internal/diagnostics"
	"github.com/kekawia/net-switch/internal/engine/protocol"
	"github.com/kekawia/net-switch/internal/service"
)

// The service logs live in the protected machine store, which only SYSTEM
// (root) and administrators can read. Control can, and already knows its
// owner, so it builds the owner's problem report: no admin prompt, and
// personal details are replaced before the text leaves the service.

// reportBudgets are the bytes of newest lines per log at full size.
var reportBudgets = struct{ control, engine, update int }{150_000, 220_000, 30_000}

// problemReport builds the report. It must fit one IPC reply even when much
// of it needs escaping, so the log budgets halve until the JSON fits.
func problemReport(data string, owner Owner, header []diagnostics.Field, source string) string {
	computer, _ := os.Hostname()
	var users []string
	if domain, user, ok := strings.Cut(owner.Name, `\`); ok {
		users = append(users, user)
		if computer == "" {
			computer = domain
		}
	} else if owner.Name != "" {
		users = append(users, owner.Name)
	}
	options := diagnostics.Options{Users: users, Computer: computer}
	intro := diagnostics.Intro(time.Now(), source)
	fields := append([]diagnostics.Field{{Name: "Version", Value: buildinfo.String()}, {Name: "System", Value: diagnostics.System()}}, header...)
	for scale := 1; ; scale *= 2 {
		text := diagnostics.Build(intro, fields, reportSources(data, scale), options)
		if b, err := json.Marshal(text); scale >= 16 || err == nil && len(b) <= protocol.MessageLimit-4096 {
			return text
		}
	}
}

func reportSources(data string, scale int) []diagnostics.Source {
	files := func(name string) []string {
		path := filepath.Join(data, name+".log")
		return []string{path + ".old", path}
	}
	return []diagnostics.Source{
		{Title: service.Control + ".log, the Net Switch service", Files: files(service.Control), Budget: reportBudgets.control / scale},
		{Title: service.Engine + ".log, the routing engine", Files: files(service.Engine), Skip: healthyHeartbeat, Shorten: shortenTimings, Budget: reportBudgets.engine / scale},
		{Title: "netswitch-update.log, updates", Files: files("netswitch-update"), Budget: reportBudgets.update / scale},
	}
}

// healthyHeartbeat is the engine host's periodic all-well line; thousands of
// them would push the lines that matter out of the report.
func healthyHeartbeat(line string) bool {
	return strings.Contains(line, "NATIVE_HEALTH ") && strings.Contains(line, " failures=0 ")
}

var (
	timingInstance  = regexp.MustCompile(`"instance":"([0-9a-f]+)"`)
	timingOperation = regexp.MustCompile(`"operation":"([a-z-]+)"`)
	timingPhase     = regexp.MustCompile(`"([A-Za-z0-9_.-]+)":\{"calls":(\d+),"totalNanos":(\d+)`)
	timingError     = regexp.MustCompile(`"error":"((?:[^"\\]|\\.)*)"`)
)

// shortenTimings turns the Windows engine's start and stop timing record
// (internal/engine/windows/timings_windows.go: 5-10 KB of JSON, 80% of a busy
// night's engine section on 2026-11-23) into its totals, three slowest steps
// and any error, so the report reaches further back. The record is matched,
// not parsed: the host's log sink cuts each line at 4 KiB, so most stop
// records are already cut in the file. The log keeps what it has.
func shortenTimings(line string) string {
	const marker = "WINDOWS LIFECYCLE {"
	i := strings.Index(line, marker)
	if i < 0 {
		return line
	}
	record := line[i+len(marker)-1:]
	instance, operation := timingInstance.FindStringSubmatch(record), timingOperation.FindStringSubmatch(record)
	phases := timingPhase.FindAllStringSubmatch(record, -1)
	if instance == nil || operation == nil || len(phases) == 0 {
		return line
	}
	type step struct {
		name         string
		nanos, calls uint64
	}
	var totals []string
	var steps []step
	for _, p := range phases {
		calls, _ := strconv.ParseUint(p[2], 10, 64)
		nanos, _ := strconv.ParseUint(p[3], 10, 64)
		if base, ok := strings.CutSuffix(p[1], ".total"); ok {
			totals = append(totals, base+" "+time.Duration(nanos).Round(time.Millisecond).String())
		} else {
			steps = append(steps, step{p[1], nanos, calls})
		}
	}
	sort.Strings(totals)
	sort.Slice(steps, func(a, b int) bool { return steps[a].nanos > steps[b].nanos })
	var slowest []string
	for _, s := range steps[:min(3, len(steps))] {
		calls := "1 call"
		if s.calls != 1 {
			calls = fmt.Sprintf("%d calls", s.calls)
		}
		slowest = append(slowest, fmt.Sprintf("%s %s (%s)", s.name, time.Duration(s.nanos).Round(time.Millisecond), calls))
	}
	out := fmt.Sprintf("%sWINDOWS LIFECYCLE instance=%s operation=%s; totals: %s; slowest: %s", line[:i], instance[1], operation[1], strings.Join(totals, ", "), strings.Join(slowest, ", "))
	if e := timingError.FindStringSubmatch(record); e != nil {
		out += "; error: " + e[1]
	}
	if !strings.HasSuffix(strings.TrimSpace(record), "}") {
		return out + " (record cut in the log)"
	}
	return out + " (full timings in the log)"
}

// reportHeader describes routing and combining as Control sees them.
func (a *Access) reportHeader() []diagnostics.Field {
	snapshot := a.Remote.Snapshot()
	fields := []diagnostics.Field{{Name: "Routing", Value: snapshot.Status}}
	if snapshot.Error != nil && *snapshot.Error != "" {
		fields = append(fields, diagnostics.Field{Name: "Routing error", Value: *snapshot.Error})
	}
	if a.Core != nil {
		for _, fact := range a.Core.CombineFacts() {
			fields = append(fields, diagnostics.Field{Name: fact[0], Value: fact[1]})
		}
	}
	return fields
}

// requestProblemReport asks Control for the owner's report. It never starts
// the services: a report must not change what it reports on.
func requestProblemReport(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := dialIPC(ctx, controlEndpoint("desktop"))
	if err != nil {
		return "", err
	}
	rpc := NewRPC(conn)
	defer rpc.Close()
	var reply struct {
		Report string `json:"report"`
	}
	if err := rpc.Call(ctx, map[string]any{"method": "diagnostics"}, &reply); err != nil {
		return "", err
	}
	return reply.Report, nil
}

// DiagnosticsCommand is `netswitchctl diagnostics`: the owner gets the report
// from Control; an administrator can still read the logs when Control does
// not answer. Without out, the report goes to standard output.
func DiagnosticsCommand(ctx context.Context, data, out string) error {
	report, err := requestProblemReport(ctx)
	if err != nil {
		if !Administrator() {
			return fmt.Errorf("Net Switch didn't send a report (%w). Run this again as administrator to read its logs directly", err)
		}
		resolved, storeErr := ResolveStore(data)
		if storeErr != nil {
			return fmt.Errorf("Net Switch didn't send a report (%v), and its logs can't be read: %w", err, storeErr)
		}
		owner, _ := LoadOwner(resolved)
		header := []diagnostics.Field{{Name: "Routing", Value: "unknown, Net Switch didn't answer: " + err.Error()}}
		report = problemReport(resolved, owner, header, "from the log files directly, because Net Switch didn't answer")
	}
	if out == "" {
		_, err := fmt.Print(report)
		return err
	}
	path, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(report), 0o600); err != nil {
		return err
	}
	fmt.Println("Saved the problem report to " + path)
	return nil
}
