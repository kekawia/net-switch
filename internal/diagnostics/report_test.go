package diagnostics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func writeLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReportKeepsTheNewestLinesAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "NetSwitch.log")
	writeLog(t, log+".old", "old 1", "old 2", "old 3")
	writeLog(t, log, "new 1", "NATIVE_HEALTH failures=0 ", "new 2")
	skip := func(line string) bool { return strings.HasPrefix(line, "NATIVE_HEALTH") }
	// Room for the two current lines and the last rotated one only.
	text := Build("", nil, []Source{{Title: "NetSwitch.log", Files: []string{log + ".old", log}, Skip: skip, Budget: len("old 3\nnew 1\nnew 2\n")}}, Options{})
	want := "\n--- NetSwitch.log: newest 3 lines, 1 routine line left out ---\nold 3\nnew 1\nnew 2\n"
	if text != want {
		t.Fatalf("\n got: %q\nwant: %q", text, want)
	}
}

func TestReportSaysWhenALogIsMissing(t *testing.T) {
	text := Build("", nil, []Source{{Title: "NetSwitchEngine.log", Files: []string{filepath.Join(t.TempDir(), "missing.log")}, Budget: 1000}}, Options{})
	if !strings.Contains(text, "newest 0 lines ---\n(no lines)\n") {
		t.Fatalf("missing log not reported: %q", text)
	}
}

// A file larger than the read window starts mid-line: that partial line is
// dropped, never shown as if it were whole.
func TestReportDropsThePartialFirstLineOfALargeLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "NetSwitchEngine.log")
	line := strings.Repeat("x", 99) // 100 bytes with its newline
	var b strings.Builder
	for i := 0; b.Len() < rawWindow+500; i++ {
		fmt.Fprintf(&b, "%06d %s\n", i, line[7:])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	seen := 0
	if err := eachLine(path, func(l string) {
		if seen++; len(strings.TrimRight(l, "\n")) != 99 {
			t.Fatalf("partial or merged line %d: %q", seen, l)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if seen < rawWindow/100-2 {
		t.Fatalf("only %d lines read from the window", seen)
	}
}

func TestReportCutsRunawayLinesAndControlCharacters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "NetSwitch.log")
	// The 200 KB line is longer than the 64 KB read buffer.
	writeLog(t, path, "bell\x07 escape\x1b[31m tab\tkept", strings.Repeat("é", maxLine), strings.Repeat("x", 200<<10), "after the long line")
	text := Build("", nil, []Source{{Title: "c", Files: []string{path}, Budget: 1 << 20}}, Options{})
	if !strings.Contains(text, "bell escape[31m tab\tkept\n") {
		t.Fatalf("control characters kept: %q", text[:80])
	}
	if strings.Count(text, " … [line cut]\n") != 2 || !utf8.ValidString(text) {
		t.Fatal("long lines were not cut on a character boundary")
	}
	if !strings.HasSuffix(text, "\nafter the long line\n") || len(text) > 3*maxLine {
		t.Fatalf("the line after a very long one was lost, or the long one kept (%d bytes)", len(text))
	}
}

// A PC that stops suddenly can leave zero bytes where the log's end was not
// written; the next start's line may follow them on the same "line".
func TestReportNamesUnwrittenLogBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "NetSwitchEngine.log")
	zeros := strings.Repeat("\x00", 2*maxLine)
	writeLog(t, path, "before the stop", zeros, zeros+"2026-11-22T13:00:00Z native startup: native-enter")
	text := Build("", nil, []Source{{Title: "e", Files: []string{path}, Budget: 1 << 20}}, Options{})
	want := "before the stop\n" + unwritten + "\n2026-11-22T13:00:00Z native startup: native-enter\n"
	if !strings.HasSuffix(text, want) {
		t.Fatalf("\n got: %q\nwant suffix: %q", text, want)
	}
}

// The fixed opening explains the labels in plain words, so redaction must
// not touch it; the header and log lines are redacted.
func TestReportRedactsTheBodyButNotTheIntro(t *testing.T) {
	path := filepath.Join(t.TempDir(), "NetSwitch.log")
	writeLog(t, path, `owner=PC-1\user reconnect C:\Users\user\x.exe`)
	intro := Intro(time.Date(2026, 11, 23, 5, 0, 0, 0, time.UTC), "a test")
	text := Build(intro, []Field{{Name: "Routing error", Value: `open C:\Users\user\y: denied`}}, []Source{{Title: "c", Files: []string{path}, Budget: 1000}}, Options{Users: []string{"user"}, Computer: "PC-1"})
	if !strings.HasPrefix(text, intro) || !strings.Contains(intro, "so [user-1] is the same account everywhere") {
		t.Fatal("intro changed:", text)
	}
	body := strings.TrimPrefix(text, intro)
	if strings.Contains(body, `\user\`) || strings.Contains(body, `\user `) || strings.Contains(body, "PC-1") {
		t.Fatal("personal details left in the body:", body)
	}
	if !strings.Contains(body, `Routing error: open C:\Users\[user-1]\y: denied`) || !strings.Contains(body, `owner=[computer]\[user-1]`) {
		t.Fatal("header or log not redacted as expected:", body)
	}
}
