package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

// Original async ordering is projected from named native operations, not read
// back out of the trace being checked. A revision has one ack with ordered lane
// members; the native worker snapshot replaces several same-time legacy reads.
// Each projection retains the position of its actual, already-compared effect.
type startupCounterpart struct {
	kind, identity string
	source         int
}
type startupCounterparts struct {
	want []startupCounterpart
	next int
	cmp  *nativeTraceComparator
}

func newStartupCounterparts(files *memoryFiles, cmp *nativeTraceComparator, first, second string, migration, votes bool) *startupCounterparts {
	c := &startupCounterparts{cmp: cmp}
	find := func(key string) int {
		for i, k := range files.order {
			if k == key {
				return i
			}
		}
		return -1
	}
	logs := []int{}
	for i, k := range files.order {
		if k == "log" || k == "lane-log" {
			logs = append(logs, i)
		}
	}
	add := func(kind, identity string, source int) {
		c.want = append(c.want, startupCounterpart{kind, identity, source})
	}
	logAt := func(i int) int {
		if i >= len(logs) {
			return -1
		}
		return logs[i]
	}
	log := func(i int) { add("log", "", logAt(i)) }
	appendLog := func(i int) { add("async-result", "log.append", logAt(i)) }
	i := 0
	if migration {
		log(i)
		appendLog(i)
		i++
	}
	log(i)
	log(i + 1)
	appendLog(i)
	appendLog(i + 1)
	i += 2
	for _, op := range []string{"platform.isElevated", "platform.detectAdapters", "platform.readMinimizeConnectionsPolicy"} {
		key := "platform:network"
		if op == "platform.isElevated" {
			key = "platform:elevated"
		}
		add("async-result", op, find(key))
	}
	log(i)
	appendLog(i)
	i++ // session announcement
	add("counter-sample", "Ethernet", find("native:initial-poll"))
	if second != "" {
		add("counter-sample", "Wi-Fi", find("native:initial-poll"))
	}
	networkOps := []string{"platform.detectAdapters", "platform.readDefaultRoutes"}
	if second != "" {
		networkOps = append(networkOps, "platform.readDefaultRoutes")
	}
	for _, op := range networkOps {
		add("async-result", op, find("platform:network"))
	}
	log(i)
	appendLog(i)
	i++ // routing starting
	add("async-result", "log.rotate", find("native:start"))
	add("engine", "GET /version", find("native:started"))
	add("engine-reply", "/version", find("native:started"))
	log(i)
	appendLog(i)
	i++ // routing on
	if second == "" {
		return c
	}
	for n, line := range []string{first, second} {
		add("engine", "PUT /proxies/lane-"+line, find("native:ack"))
		add("engine-reply", "/proxies/lane-"+line, find("native:ack"))
		add("async-result", "platform.readDefaultRoutes", find("platform:network"))
		add("engine", "GET /proxies/line-"+line+"/delay", find("native:probe:"+line))
		add("probe-result", "/proxies/line-"+line+"/delay", find("native:probe-result:"+line))
		if votes && n == 1 {
			add("probe-vote", first, find("native:probe-result:"+first))
		}
		log(i)
		appendLog(i)
		i++
		add("async-result", "engine./proxies/line-"+line+"/delay.json", find("native:probe-result:"+line))
	}
	if votes {
		add("probe-vote", second, find("native:probe-result:"+second))
	}
	return c
}

func (c *startupCounterparts) Observe(entry replayledger.Entry) error {
	switch entry.Kind {
	case "log", "async-result", "engine", "engine-reply", "probe-result", "probe-vote", "event", "counter-sample":
	default:
		return nil
	}
	var v struct{ Operation, Method, Route, Line, Kind, LineID, Alias string }
	if err := json.Unmarshal(entry.Value, &v); err != nil {
		return err
	}
	id := ""
	switch entry.Kind {
	case "log":
	case "event":
		id = v.Kind + " " + v.LineID
	case "counter-sample":
		id = v.Alias
	case "async-result":
		id = v.Operation
	case "engine":
		id = v.Method + " " + v.Route
	case "engine-reply", "probe-result":
		id = v.Route
	case "probe-vote":
		id = v.Line
	default:
		return nil
	}
	if c.next >= len(c.want) {
		return fmt.Errorf("unexpected native counterpart %d %s %s", entry.Seq, entry.Kind, id)
	}
	w := c.want[c.next]
	if w.kind != entry.Kind || w.identity != id {
		return fmt.Errorf("ordered native counterpart at %d: got %s %s, want %s %s", entry.Seq, entry.Kind, id, w.kind, w.identity)
	}
	if w.source < 0 || w.source >= c.cmp.effectNext {
		return fmt.Errorf("counterpart %d lacks consumed native source position %d", entry.Seq, w.source)
	}
	c.next++
	return nil
}
func (c *startupCounterparts) Finish() error {
	if c.next != len(c.want) {
		return fmt.Errorf("leftover native counterparts: %d", len(c.want)-c.next)
	}
	return nil
}

// One cursor over actual file calls. Only explicitly named native-only calls
// (journal/recovery and the migration mirror repair) are folded into groups.
// Every other read/write/rename must match the next original file operation.
type startupFileCursor struct {
	files        *memoryFiles
	next         int
	legacy       bool
	pending      map[string]recordedFileResult
	published    map[string]bool
	renames      map[string]int
	repair       map[string][]byte
	revisionAcks map[int]bool
}

func newStartupFileCursor(files *memoryFiles, legacy bool) *startupFileCursor {
	return &startupFileCursor{files: files, legacy: legacy, pending: map[string]recordedFileResult{}, published: map[string]bool{}, renames: map[string]int{}, repair: map[string][]byte{}}
}
func startupFileName(path string) string {
	base := filepath.Base(path)
	for _, name := range []string{"control-journal.json.bak", "control-journal.json", "settings.json.bak", "settings.json", "windows-undo.json", "usage.recovery.json", "usage.json", "server.json"} {
		if base == name || strings.HasPrefix(base, name+".") {
			return name
		}
	}
	return base
}
func (c *startupFileCursor) record(r recordedFileResult) error {
	name := startupFileName(r.Path)
	if r.Operation == "readFile" {
		return nil
	}
	if r.Err != nil {
		return fmt.Errorf("native file operation failed: %+v", r)
	}
	switch r.Operation {
	case "writeFile":
		if _, ok := c.pending[name]; ok {
			return fmt.Errorf("duplicate write before rename: %s", name)
		}
		c.pending[name] = r
		c.published[name] = false
	case "rename":
		p, ok := c.pending[name]
		if !ok || p.Path != r.Path || filepath.Base(r.Destination) != name || !bytes.Equal(p.Bytes, r.Bytes) {
			return fmt.Errorf("rename without its exact successful write: %s", name)
		}
		delete(c.pending, name)
		delete(c.published, name)
		c.renames[name]++
		if c.legacy && strings.HasPrefix(name, "settings.json") && c.renames[name] == 1 {
			c.repair[name] = append([]byte(nil), r.Bytes...)
		}
	default:
		return fmt.Errorf("unknown native file operation %s", r.Operation)
	}
	return nil
}
func (c *startupFileCursor) skipNative() error {
	for c.next < len(c.files.fileResults) {
		r := c.files.fileResults[c.next]
		name := startupFileName(r.Path)
		native := strings.HasPrefix(name, "control-journal.json") || name == "usage.recovery.json"
		repair := c.legacy && (name == "settings.json" || name == "settings.json.bak") && c.renames[name] == 1 && r.Operation != "readFile"
		if !native && !repair {
			break
		}
		if r.Operation == "readFile" && !errors.Is(r.Err, fs.ErrNotExist) {
			return fmt.Errorf("native-only initial read must be missing: %s", name)
		}
		if repair && !bytes.Equal(r.Bytes, c.repair[name]) {
			return fmt.Errorf("migration repair differs from its first publication: %s", name)
		}
		if err := c.record(r); err != nil {
			return err
		}
		c.next++
	}
	return nil
}
func (c *startupFileCursor) Observe(entry replayledger.Entry) (bool, error) {
	var v struct {
		Operation, File, Code string
		OK                    bool
	}
	if err := json.Unmarshal(entry.Value, &v); err != nil {
		return false, err
	}
	name := startupFileName(v.File)
	switch name {
	case "settings.json", "settings.json.bak", "windows-undo.json", "usage.json", "server.json":
	default:
		return false, nil
	}
	if err := c.skipNative(); err != nil {
		return true, err
	}
	if c.next == len(c.files.fileResults) {
		return true, fmt.Errorf("missing native file operation for %d: %s %s", entry.Seq, v.Operation, name)
	}
	r := c.files.fileResults[c.next]
	if r.Operation != v.Operation || startupFileName(r.Path) != name {
		return true, fmt.Errorf("ordered file operation at %d: got %s %s, want %s %s", entry.Seq, r.Operation, startupFileName(r.Path), v.Operation, name)
	}
	if (r.Err == nil) != v.OK || r.Err != nil && (!errors.Is(r.Err, fs.ErrNotExist) || v.Code != "ENOENT") {
		return true, fmt.Errorf("file completion result differs at %d", entry.Seq)
	}
	if r.Operation == "rename" && !c.published[name] {
		return true, fmt.Errorf("rename without checked publication at %d: %s", entry.Seq, name)
	}
	if err := c.record(r); err != nil {
		return true, err
	}
	c.next++
	return true, nil
}
func (c *startupFileCursor) Publication(name string, want []byte) error {
	r, ok := c.pending[name]
	if !ok || c.published[name] {
		return fmt.Errorf("publication without distinct preceding write: %s", name)
	}
	a, err := orderedTraceJSON(r.Bytes)
	if err != nil {
		return err
	}
	b, err := orderedTraceJSON(want)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(a, b) {
		return fmt.Errorf("ordered file publication %s: %s", name, firstDifference(a, b, "$"))
	}
	c.published[name] = true
	return nil
}
func (c *startupFileCursor) Finish() error {
	if err := c.skipNative(); err != nil {
		return err
	}
	if c.next != len(c.files.fileResults) || len(c.pending) != 0 {
		return fmt.Errorf("leftover file operations: consumed %d/%d pending %v", c.next, len(c.files.fileResults), c.pending)
	}
	return nil
}

func TestStartupCounterpartsRejectReordering(t *testing.T) {
	for _, pair := range [][2]startupCounterpart{
		{{kind: "async-result", identity: "log.append", source: 0}, {kind: "async-result", identity: "engine./proxies/line-a1/delay.json", source: 1}},
		{{kind: "engine", identity: "GET /proxies/line-a1/delay", source: 0}, {kind: "probe-result", identity: "/proxies/line-a1/delay", source: 1}},
		{{kind: "event", identity: "exhausted a1", source: 0}, {kind: "log", source: 1}},
		{{kind: "counter-sample", identity: "Ethernet", source: 0}, {kind: "counter-sample", identity: "Wi-Fi", source: 1}},
	} {
		t.Run(pair[0].kind, func(t *testing.T) {
			c := startupCounterparts{want: pair[:], cmp: &nativeTraceComparator{effectNext: 2}}
			v := map[string]any{"operation": pair[1].identity, "route": pair[1].identity, "alias": pair[1].identity}
			e := replayledger.Entry{Seq: 1, Kind: pair[1].kind, Value: mustStartupJSON(t, v)}
			if err := c.Observe(e); err == nil {
				t.Fatal("out-of-order counterpart accepted")
			}
			if c.next != 0 {
				t.Fatal("failed observation advanced cursor")
			}
			if err := c.Finish(); err == nil {
				t.Fatal("unconsumed counterpart accepted")
			}
		})
	}
}

func TestStartupFilesRequireDistinctWrites(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(fmt.Sprint("missing-second=", missing), func(t *testing.T) {
			f := &memoryFiles{}
			for n := 1; n <= 2; n++ {
				path := fmt.Sprintf("/test/settings.json.%d.tmp", n)
				body := []byte(fmt.Sprintf(`{"value":%d}`, n))
				if !missing || n != 2 {
					f.fileResults = append(f.fileResults, recordedFileResult{Operation: "writeFile", Path: path, Bytes: body})
				}
				f.fileResults = append(f.fileResults, recordedFileResult{Operation: "rename", Path: path, Destination: "/test/settings.json", Bytes: body})
			}
			c := newStartupFileCursor(f, false)
			for n := 1; n <= 2; n++ {
				e := replayledger.Entry{Seq: n, Kind: "file-completion", Value: json.RawMessage(`{"operation":"writeFile","file":"/oracle/data/settings.json.old.tmp","ok":true}`)}
				matched, err := c.Observe(e)
				if missing && n == 2 {
					if !matched || err == nil {
						t.Fatal("missing second write reused first result")
					}
					return
				}
				if !matched || err != nil {
					t.Fatal(matched, err)
				}
				if err := c.Publication("settings.json", []byte(fmt.Sprintf(`{"value":%d}`, n))); err != nil {
					t.Fatal(err)
				}
				e.Value = json.RawMessage(`{"operation":"rename","file":"/oracle/data/settings.json.old.tmp","ok":true}`)
				if matched, err := c.Observe(e); !matched || err != nil {
					t.Fatal(matched, err)
				}
			}
			if err := c.Finish(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
