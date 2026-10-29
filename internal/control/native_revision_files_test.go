package control

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/replayledger"
)

const revisionFileProof = "ordered rule-file projection of acknowledged native revision"

// This ordered projection extends the file cursor without inventing native
// adapter-file I/O. The caller supplies an independent, complete file plan and
// has already checked the full literal native revision and its effect stream.
// Each plan binds to a distinct consumed native acknowledgement. In particular,
// the legacy combine+block double write is one explicitly repeated plan, not
// permission to reuse a previous file observation or native acknowledgement.
func (c *startupFileCursor) CheckRevision(entries []replayledger.Entry, names []string, cmp *nativeTraceComparator, from int) (map[int]string, error) {
	if from < 0 || from > cmp.effectNext || cmp.effects == nil || cmp.effectNext > len(*cmp.effects) {
		return nil, fmt.Errorf("rule revision lacks checked native interval")
	}
	ack := -1
	for i := from; i < cmp.effectNext; i++ {
		if (*cmp.effects)[i] != "native:ack" {
			continue
		}
		if ack >= 0 || i == from || (*cmp.effects)[i-1] != "native:apply" {
			return nil, fmt.Errorf("rule revision has ambiguous native acknowledgement")
		}
		ack = i
	}
	if len(names) > 0 && (ack < 0 || c.revisionAcks[ack]) {
		return nil, fmt.Errorf("rule revision requires distinct checked native acknowledgement")
	}
	next, phase := 0, 0
	temporary := ""
	usedTemporary := map[string]bool{}
	checked := map[int]string{}
	for _, entry := range entries {
		if entry.Kind != "write" && entry.Kind != "file-completion" {
			continue
		}
		var value struct {
			File, Operation string
			OK              bool
		}
		if err := json.Unmarshal(entry.Value, &value); err != nil {
			return nil, err
		}
		base := value.File[strings.LastIndex(value.File, "/")+1:]
		if !strings.HasPrefix(base, "apps-") && !strings.HasPrefix(base, "share-") && !strings.HasPrefix(base, "cut-") {
			if next < len(names) {
				return nil, fmt.Errorf("incomplete rule-file revision before %d: %s", entry.Seq, value.File)
			}
			continue
		}
		if next == len(names) {
			return nil, fmt.Errorf("extra rule-file observation at %d: %s", entry.Seq, value.File)
		}
		file := "/oracle/data/" + names[next]
		operation := []string{"writeFile", "write", "rename"}[phase]
		valid := entry.Kind == "file-completion" && entry.Direction == "input" && value.OK && value.Operation == operation
		switch phase {
		case 0:
			valid = valid && strings.HasPrefix(value.File, file+".") && strings.HasSuffix(value.File, ".tmp") && !usedTemporary[value.File]
		case 1:
			valid = entry.Kind == "write" && entry.Direction == "output" && value.File == file
		case 2:
			valid = valid && value.File == temporary
		}
		if !valid {
			return nil, fmt.Errorf("ordered rule-file guard at %d: got %s %s %s; want %s %s", entry.Seq, entry.Kind, value.Operation, value.File, operation, file)
		}
		if _, exists := checked[entry.Seq]; exists {
			return nil, fmt.Errorf("reused rule-file entry %d", entry.Seq)
		}
		if phase == 0 {
			temporary = value.File
			usedTemporary[temporary] = true
		}
		checked[entry.Seq] = revisionFileProof
		phase++
		if phase == 3 {
			next++
			phase = 0
			temporary = ""
		}
	}
	if next != len(names) || phase != 0 {
		return nil, fmt.Errorf("incomplete rule-file revision: completed %d/%d files, phase %d", next, len(names), phase)
	}
	if len(names) > 0 {
		if c.revisionAcks == nil {
			c.revisionAcks = map[int]bool{}
		}
		c.revisionAcks[ack] = true
	}
	return checked, nil
}

func twoLineRevisionFiles() []string {
	return []string{"apps-a1.json", "apps-b2.json", "share-b2.json", "cut-b2.json"}
}

func TestRevisionFilesRejectMutations(t *testing.T) {
	m, err := replayledger.DefaultMapping()
	if err != nil {
		t.Fatal(err)
	}
	traces, err := replayledger.Load("../..", m)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name       string
		begin, end int
		copies     int
	}{
		{"combining", 129, 162, 1}, {"capMoved", 142, 173, 1},
		{"combiningNoOpenLine", 208, 272, 2}, {"capBlockedAndMainException", 208, 249, 1},
		{"capReset", 149, 190, 1}, {"capReset", 196, 239, 1}, {"midnightGap", 143, 184, 1},
	} {
		t.Run(fmt.Sprintf("%s-%d", fixture.name, fixture.begin), func(t *testing.T) {
			var original []replayledger.Entry
			for _, trace := range traces {
				if trace.Name == fixture.name {
					original = trace.Entries[fixture.begin+1 : fixture.end]
				}
			}
			if len(original) == 0 {
				t.Fatal("missing fixture interval")
			}
			for _, mutation := range []string{"valid", "drop-cut", "duplicate-share", "rename-first", "drop-publication", "duplicate-publication", "wrong-temp", "missing-ack", "reuse-ack"} {
				t.Run(mutation, func(t *testing.T) {
					entries := append([]replayledger.Entry(nil), original...)
					changed := false
					for i := 0; i < len(entries); i++ {
						e := &entries[i]
						if e.Kind != "write" && e.Kind != "file-completion" {
							continue
						}
						var v map[string]any
						if err := json.Unmarshal(e.Value, &v); err != nil {
							t.Fatal(err)
						}
						file, _ := v["file"].(string)
						if !strings.Contains(file, "cut-b2.json") {
							continue
						}
						switch mutation {
						case "drop-cut":
							entries = append(entries[:i], entries[i+1:]...)
							i--
							changed = true
							continue
						case "duplicate-share":
							v["file"] = strings.Replace(file, "cut-b2.json", "share-b2.json", 1)
							changed = true
						case "rename-first":
							if v["operation"] == "writeFile" {
								v["operation"] = "rename"
								changed = true
							}
						case "wrong-temp":
							if v["operation"] == "rename" {
								v["file"] = file + ".other.tmp"
								changed = true
							}
						case "drop-publication":
							if e.Kind == "write" {
								entries = append(entries[:i], entries[i+1:]...)
								i--
								changed = true
								continue
							}
						case "duplicate-publication":
							if e.Kind == "write" && !changed {
								copy := *e
								entries = append(entries[:i+1], append([]replayledger.Entry{copy}, entries[i+1:]...)...)
								i++
								changed = true
							}
						}
						// Replace only decoded copies; no frozen trace is written.
						entries[i].Value, _ = json.Marshal(v)
					}
					effects := []string{"native:apply", "native:ack"}
					cmp := &nativeTraceComparator{effects: &effects, effectNext: 2}
					cursor := newStartupFileCursor(&memoryFiles{}, false)
					names := twoLineRevisionFiles()
					if fixture.copies == 2 {
						names = append(names, twoLineRevisionFiles()...)
					}
					if mutation == "missing-ack" {
						cmp.effectNext = 1
						changed = true
					}
					if mutation == "reuse-ack" {
						if _, err := cursor.CheckRevision(original, names, cmp, 0); err != nil {
							t.Fatal(err)
						}
						changed = true
					}
					_, err := cursor.CheckRevision(entries, names, cmp, 0)
					if mutation == "valid" {
						if err != nil {
							t.Fatal(err)
						}
					} else if !changed || err == nil {
						t.Fatalf("mutation %s accepted: changed=%v", mutation, changed)
					}
				})
			}
		})
	}
}
