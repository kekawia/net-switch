package control

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	js "github.com/AyoubAchour/net-switch/internal/jsvalue"
)

type traceEntry struct {
	Seq       int             `json:"seq"`
	Direction string          `json:"direction"`
	Kind      string          `json:"kind"`
	Value     json.RawMessage `json:"value"`
}
type recordedTrace struct {
	Version  int          `json:"version"`
	Name     string       `json:"name"`
	Entries  []traceEntry `json:"entries"`
	Scenario struct {
		Timezone    string         `json:"timezone"`
		Now         *int64         `json:"now"`
		Environment map[string]any `json:"environment"`
		Steps       []struct {
			Kind                string `json:"kind"`
			MS                  int64  `json:"ms"`
			Method, Route, Line string
			Body                json.RawMessage   `json:"body"`
			Headers             map[string]string `json:"headers"`
			Value               json.RawMessage   `json:"value"`
		} `json:"steps"`
	} `json:"scenario"`
}

// Section 4.5 adds Quad9 to the inherited defaults; the window must describe
// those same three targets. Explicit user target lists retain exact parity.
func operatorStateExpectation(state map[string]any, custom bool) {
	settings := js.Object(state["settings"])
	if !custom && reflect.DeepEqual(settings["probeTargets"], []any{"1.1.1.1:443", "8.8.8.8:443"}) {
		settings["probeTargets"] = []any{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	}
}

func traceLogKey(text string) string {
	if strings.Contains(text, "'s apps now use ") {
		return "lane-log"
	}
	if strings.HasPrefix(text, "combining shares:") {
		return "shares-log"
	}
	if strings.Contains(text, "their new connections are refused until the cap resets") {
		return "blocked-log"
	}
	return "log"
}

func firstDifference(a, b any, path string) string {
	if reflect.DeepEqual(a, b) {
		return ""
	}
	if am, ok := a.(map[string]any); ok {
		if bm, ok := b.(map[string]any); ok {
			keys := []string{}
			for k := range am {
				keys = append(keys, k)
			}
			for k := range bm {
				if _, ok := am[k]; !ok {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				av, ap := am[k]
				bv, bp := bm[k]
				if ap != bp {
					return path + "." + k + ": field presence differs"
				}
				if d := firstDifference(av, bv, path+"."+k); d != "" {
					return d
				}
			}
		}
	}
	if aa, ok := a.([]any); ok {
		if bb, ok := b.([]any); ok {
			if len(aa) != len(bb) {
				return fmt.Sprintf("%s: length %d != %d", path, len(aa), len(bb))
			}
			for i := range aa {
				if d := firstDifference(aa[i], bb[i], fmt.Sprintf("%s[%d]", path, i)); d != "" {
					return d
				}
			}
		}
	}
	return fmt.Sprintf("%s: got %v, want %v", path, a, b)
}

func engineFile(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	return base == "engine-config.json" || base == "engine.pid" || strings.HasPrefix(base, "apps-") || strings.HasPrefix(base, "share-") || strings.HasPrefix(base, "cut-")
}
func normalizeResourceString(s string, mapping map[string]string) string {
	if strings.HasPrefix(s, "/proxies/lane-") {
		id := strings.TrimPrefix(s, "/proxies/lane-")
		if v, ok := mapping[id]; ok {
			return "/proxies/lane-" + v
		}
	}
	if v, ok := mapping[s]; ok {
		return v
	}
	for from, to := range mapping {
		for _, prefix := range []string{"line-", "lane-", "apps-", "share-", "cut-"} {
			if s == prefix+from {
				return prefix + to
			}
			if s == prefix+from+".json" {
				return prefix + to + ".json"
			}
		}
	}
	resource := strings.ReplaceAll(s, `\`, "/")
	if resource == "/test/engine/sing-box.exe" {
		return "/oracle/engine/sing-box.exe"
	}
	if strings.HasPrefix(resource, "/test/") {
		return "/oracle/data/" + normalizeResourceString(strings.TrimPrefix(resource, "/test/"), mapping)
	}
	return s
}
func rewriteTraceStrings(b []byte, convert func(string) string) ([]byte, error) {
	out := []byte{}
	for i := 0; i < len(b); {
		if b[i] != '"' {
			out = append(out, b[i])
			i++
			continue
		}
		end := i + 1
		for end < len(b) {
			if b[end] == '\\' {
				end += 2
				continue
			}
			if b[end] == '"' {
				break
			}
			end++
		}
		if end >= len(b) {
			return nil, fmt.Errorf("unterminated JSON string")
		}
		var text string
		if err := json.Unmarshal(b[i:end+1], &text); err != nil {
			return nil, err
		}
		next := convert(text)
		if next == text {
			out = append(out, b[i:end+1]...)
		} else {
			out = append(out, js.MarshalString(next)...)
		}
		i = end + 1
	}
	return out, nil
}
func controlFile(path string) bool {
	base := filepath.Base(strings.ReplaceAll(path, `\`, "/"))
	return base == "server.json" || base == "settings.json" || base == "settings.json.bak" || base == "usage.json" || base == "windows-undo.json" || base == "windows-undo.json.bak"
}
func orderedTraceJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	var read func(string) (any, error)
	read = func(key string) (any, error) {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			m := map[string]any{}
			entries := []any{}
			for d.More() {
				t, err := d.Token()
				if err != nil {
					return nil, err
				}
				name := t.(string)
				v, err := read(name)
				if err != nil {
					return nil, err
				}
				m[name] = v
				entries = append(entries, []any{name, v})
			}
			if _, err := d.Token(); err != nil {
				return nil, err
			}
			if key == "appLines" || key == "shares" {
				return entries, nil
			}
			return m, nil
		case json.Delim('['):
			a := []any{}
			for d.More() {
				v, err := read("")
				if err != nil {
					return nil, err
				}
				a = append(a, v)
			}
			_, err := d.Token()
			return a, err
		}
		return token, nil
	}
	return read("")
}
