package control

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
)

// node.json's negative routes are outside the 7,894 trace-entry denominator.
// Keep their whole HTTP contracts, not merely a hand-written list of statuses.
func TestNativeNodeNegativeHTTPContracts(t *testing.T) {
	b, err := os.ReadFile("../../tests/oracle/fixtures/node.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Routes []struct {
			Method, Route string
			Input         json.RawMessage
			Headers       map[string]string
			Response      struct {
				Status  int
				Headers map[string]string
				Body    json.RawMessage
			}
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, tc := range fixture.Routes {
		if tc.Response.Status < 400 {
			continue
		}
		cases++
		t.Run(fmt.Sprintf("%02d-%s", cases, tc.Route), func(t *testing.T) {
			c, base, _, files := testCore(t, map[string]any{"lines": testLines()})
			c.op.ServiceMode = true
			e := &nativeStartupEngine{fakeEngine: base, files: files, want: twoLineNativeConfig(map[string]string{})}
			base.ackPoint = 1
			c.op.Engine = e
			if err := c.Poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			before := e.Snapshot()
			if before.Status != "on" || before.AppliedRevision == 0 || e.active == nil || c.quitting {
				t.Fatal("native HTTP starting state")
			}
			calls, writes, logs := len(e.calls), len(files.writes), len(files.logs)
			var body []byte
			if len(tc.Input) > 0 {
				var raw string
				if json.Unmarshal(tc.Input, &raw) == nil {
					body = []byte(raw)
				} else {
					var marker struct {
						Bytes  int
						SHA256 string
					}
					if err := json.Unmarshal(tc.Input, &marker); err != nil {
						t.Fatal(err)
					}
					if marker.Bytes != 0 {
						if marker.Bytes != 65537 {
							t.Fatal("unknown oversized input")
						}
						body = []byte(strings.Repeat(" ", marker.Bytes))
						// record.mjs hashes JSON.stringify(input), not raw HTTP bytes.
						encoded, err := json.Marshal(string(body))
						if err != nil {
							t.Fatal(err)
						}
						if fmt.Sprintf("%x", sha256.Sum256(encoded)) != marker.SHA256 {
							t.Fatal("oversized oracle bytes differ")
						}
					} else {
						body = tc.Input
					}
				}
			}
			r := httptest.NewRequest(tc.Method, "http://127.0.0.1:47821"+tc.Route, bytes.NewReader(body))
			r.Header.Set("X-Token", "native-boundary")
			for k, v := range tc.Headers {
				if strings.EqualFold(k, "host") {
					r.Host = v
				} else {
					r.Header.Set(k, v)
				}
			}
			w := httptest.NewRecorder()
			(&HTTP{Core: c, Port: 47821, Token: "native-boundary"}).ServeHTTP(w, r)
			headers := map[string]string{}
			for k := range w.Header() {
				headers[k] = w.Header().Get(k)
			}
			if w.Code != tc.Response.Status || !reflect.DeepEqual(headers, tc.Response.Headers) || !reflect.DeepEqual(replayJSON(t, w.Body.Bytes()), replayJSON(t, tc.Response.Body)) {
				t.Fatalf("negative HTTP contract: %d %v %s", w.Code, headers, w.Body.Bytes())
			}
			if len(e.calls) != calls || len(files.writes) != writes || len(files.logs) != logs || len(files.removes) != 0 || len(files.events) != 0 || !reflect.DeepEqual(e.Snapshot(), before) {
				t.Fatalf("rejected request mutated native state: calls %v writes %d logs %v snapshot %+v", e.calls[calls:], len(files.writes)-writes, files.logs[logs:], e.Snapshot())
			}
		})
	}
	if cases != 12 {
		t.Fatal("negative node.json case count", cases)
	}
}
