package diagnostics

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kekawia/net-switch/internal/sharedfile"
)

// Source is one log in the report: its files oldest first (a rotated
// ".old" before the live file), the lines to leave out, an optional way to
// shorten bulky lines, and how many bytes of the newest kept lines to include.
type Source struct {
	Title   string
	Files   []string
	Skip    func(line string) bool
	Shorten func(line string) string
	Budget  int
}

// Field is one header line, such as the version or the routing status.
type Field struct{ Name, Value string }

// rawWindow bounds how much of each file is read to find Budget bytes of kept
// lines. The logs rotate at 5 MB, so this covers a whole file; lines are
// streamed, so only the kept ones are held in memory (Control runs with a
// 32 MiB memory limit). The engine log is mostly heartbeats that are left out.
const rawWindow = 6 << 20

// maxLine cuts a long line, such as the engine's start and stop timings, so a
// few of them cannot push hours of events out of the report. The full lines
// stay in the log files.
const maxLine = 4 << 10

// Intro is the report's fixed opening, kept out of redaction so a person
// whose account is called "user" still reads it whole. source says where the
// lines came from, such as "from the running Net Switch".
func Intro(now time.Time, source string) string {
	return strings.Join([]string{
		"Net Switch problem report",
		"Made " + now.UTC().Format("2006-01-02 15:04") + " UTC " + source + ".",
		"",
		"Your personal details are replaced with labels: user and computer names,",
		"email addresses, public IP addresses, hardware addresses and IDs. Each label",
		"stands for one thing, so [user-1] is the same account everywhere.",
		"Nothing has been sent anywhere. Read it before you share it.",
		"",
		"",
	}, "\n")
}

// Build returns the report: Intro, then the header and the newest lines of
// each source, with personal details replaced.
func Build(intro string, header []Field, sources []Source, o Options) string {
	var body strings.Builder
	for _, f := range header {
		fmt.Fprintf(&body, "%s: %s\n", f.Name, f.Value)
	}
	for _, s := range sources {
		lines, skipped, notes := newest(s)
		title := fmt.Sprintf("--- %s: newest %s", s.Title, count(len(lines), "line"))
		if skipped > 0 {
			title += fmt.Sprintf(", %s left out", count(skipped, "routine line"))
		}
		fmt.Fprintf(&body, "\n%s ---\n", title)
		for _, note := range notes {
			body.WriteString("(" + note + ")\n")
		}
		for _, line := range lines {
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	return intro + Redact(body.String(), o)
}

// newest keeps the newest lines of a source's files within its budget.
func newest(s Source) (lines []string, skipped int, notes []string) {
	size := 0
	add := func(line string) {
		lines = append(lines, line)
		size += len(line) + 1
		for size > s.Budget && len(lines) > 0 {
			size -= len(lines[0]) + 1
			lines = lines[1:]
		}
	}
	keep := func(line string) {
		line = strings.TrimRight(line, "\r\n")
		if strings.Count(line, "\x00") >= 16 && (len(lines) == 0 || lines[len(lines)-1] != unwritten) {
			add(unwritten)
		}
		if s.Shorten != nil {
			line = s.Shorten(line)
		}
		if line = clean(line); line == "" {
			return
		}
		if s.Skip != nil && s.Skip(line) {
			skipped++
			return
		}
		add(line)
	}
	for _, path := range s.Files {
		if err := eachLine(path, keep); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			notes = append(notes, "could not read "+baseName(path)+": "+err.Error())
		}
	}
	if len(lines) == 0 && len(notes) == 0 {
		notes = append(notes, "no lines")
	}
	return lines, skipped, notes
}

// eachLine streams the last rawWindow bytes of path a line at a time, each
// cut to about maxLine. A read that starts mid-line skips to the next one.
func eachLine(path string, fn func(string)) error {
	file, err := sharedfile.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	partial := info.Size() > rawWindow
	if partial {
		if _, err := file.Seek(info.Size()-rawWindow, io.SeekStart); err != nil {
			return err
		}
	}
	r := bufio.NewReaderSize(io.LimitReader(file, rawWindow), 64<<10)
	for {
		line, err := readLine(r)
		if partial {
			partial = false
		} else if line != "" {
			fn(line)
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readLine returns the next line, holding at most maxLine plus one buffer of
// it however long the line really is.
func readLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		fragment, err := r.ReadSlice('\n')
		if len(line) <= maxLine {
			line = append(line, fragment...)
		}
		if err != bufio.ErrBufferFull {
			return string(line), err
		}
	}
}

// unwritten marks a run of zero bytes: what a log holds where the PC stopped
// before the file's end was written (seen 2026-11-22). The next start's line
// often follows them on the same line and is kept.
const unwritten = "[unreadable bytes left out: the log wasn't fully written, as when the PC stops suddenly]"

// clean drops control characters other than tab, then cuts a long line, so
// text that follows a run of zero bytes survives.
func clean(line string) string {
	kept := strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' || r == 0x7f {
			return -1
		}
		return r
	}, line)
	if len(kept) > maxLine {
		cut := maxLine
		for cut > 0 && !utf8.RuneStart(kept[cut]) {
			cut--
		}
		kept = kept[:cut] + " … [line cut]"
	}
	return kept
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func baseName(path string) string {
	if i := strings.LastIndexAny(path, `\/`); i >= 0 {
		return path[i+1:]
	}
	return path
}
