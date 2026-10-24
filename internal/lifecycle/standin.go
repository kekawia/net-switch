package lifecycle

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/AyoubAchour/net-switch/internal/journal"
)

// standInRefusal is the message for a data folder written by the pre-release
// stand-in build. Nothing outside CI and the owner's own test installs ever
// had one, so there is no migration: the folder is retired by hand.
const standInRefusal = "this data folder belonged to a pre-release stand-in build (sing-box adapter); run that build's uninstall or remove the folder, then install again"

// refuseStandInStore rejects a store holding stand-in state: a service
// configuration naming an adapter or proxy mode, an engine-state record (or
// its backup, when that is all that is left) without the native schema, or
// journal records of the stand-in's adapter scopes. Both the installer and the
// native host call it, so the native engine never starts over state it cannot
// interpret.
//
// Every read here is read-only. The callers do not own the engine's lifetime
// lock at this point, and the journal's own reader (FileStore.Records) opens
// the file for writing and truncates an incomplete tail, which only the owner
// may do.
func refuseStandInStore(data string) error {
	for _, name := range []string{"service-config.json", "service-config.json.bak"} {
		var c Config
		err := Read(filepath.Join(data, name), &c)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if c.Adapter != "" || c.Mode == "proxy" {
			return fmt.Errorf("%s: %s names the stand-in adapter or its proxy mode", standInRefusal, name)
		}
	}
	for _, name := range []string{"engine-state.json", "engine-state.json.bak"} {
		b, err := os.ReadFile(filepath.Join(data, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		var record struct {
			Schema int `json:"schema"`
		}
		if json.Unmarshal(b, &record) != nil || record.Schema != 1 {
			return fmt.Errorf("%s: %s has no native schema", standInRefusal, name)
		}
	}
	kinds, err := journalKinds(filepath.Join(data, "engine-journal.json"))
	if err != nil {
		return err
	}
	for _, kind := range []string{"adapter-service-scope", "adapter-linux-rule"} {
		if kinds[kind] {
			return fmt.Errorf("%s: engine-journal.json holds %q records", standInRefusal, kind)
		}
	}
	return nil
}

// journalKinds lists the record kinds an engine journal holds, reading the
// file only. It decodes the frames the way the owner does, except that an
// incomplete or undecodable final line is skipped instead of truncated: that
// is the torn write the owner recovers, and it holds no complete record to
// judge. Corruption before another complete line is refused, as the owner
// would refuse it.
func journalKinds(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	kinds := map[string]bool{}
	r := bufio.NewReaderSize(f, 64<<10)
	for {
		line, err := r.ReadBytes('\n')
		if err == io.EOF {
			return kinds, nil
		}
		if err != nil {
			return nil, err
		}
		var frame struct {
			Record  json.RawMessage `json:"record"`
			Records json.RawMessage `json:"records"`
		}
		var records []struct {
			Kind string `json:"kind"`
		}
		decodeErr := json.Unmarshal(line, &frame)
		if decodeErr == nil && len(line) <= journal.RecordLimit {
			switch {
			case frame.Records != nil:
				decodeErr = json.Unmarshal(frame.Records, &records)
			case frame.Record != nil:
				records = append(records, struct {
					Kind string `json:"kind"`
				}{})
				decodeErr = json.Unmarshal(frame.Record, &records[0])
			default:
				decodeErr = errors.New("journal frame needs one record or one record batch")
			}
		} else if decodeErr == nil {
			decodeErr = errors.New("journal record exceeds limit")
		}
		if decodeErr != nil {
			if _, peekErr := r.Peek(1); peekErr == io.EOF {
				return kinds, nil
			}
			return nil, fmt.Errorf("engine-journal.json is corrupt before its final record: %w", decodeErr)
		}
		for _, record := range records {
			kinds[record.Kind] = true
		}
	}
}
