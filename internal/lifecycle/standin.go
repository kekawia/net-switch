package lifecycle

import (
	"encoding/json"
	"fmt"
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
// may do; journal.ReadOnly decodes the same frames and leaves the tail alone.
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
	records, err := journal.ReadOnly(filepath.Join(data, "engine-journal.json"))
	if err != nil {
		return fmt.Errorf("engine-journal.json: %w", err)
	}
	for _, r := range records {
		if r.Kind == "adapter-service-scope" || r.Kind == "adapter-linux-rule" {
			return fmt.Errorf("%s: engine-journal.json holds %q records", standInRefusal, r.Kind)
		}
	}
	return nil
}
