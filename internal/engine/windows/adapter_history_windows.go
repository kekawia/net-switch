//go:build windows

package winengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AyoubAchour/net-switch/internal/sharedfile"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

type adapterHistory struct {
	Boot, GUID string
	LUID       uint64
}

type retiredLegacyAdapter struct {
	GUID string `json:"guid"`
	LUID uint64 `json:"luid"`
}

type machineAdapterHistory struct {
	Boot    string                 `json:"boot"`
	Default uint64                 `json:"defaultLuid,omitempty"`
	Legacy  []retiredLegacyAdapter `json:"legacy,omitempty"`
}

const maxRetiredLegacyAdapters = 16

// Historical identity is retained across empty journal checkpoints and process
// exit. It never authorizes deletion: PnP, IP and replacement checks still run.
// Both calls are under the lifetime lock and use the validated private directory.
func (s *diskJournal) adapterHistory(boot string) (uint64, error) {
	b, err := sharedfile.ReadFile(s.file.Path+".adapter", 1024)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var record adapterHistory
	if len(b) > 1024 || json.Unmarshal(b, &record) != nil || record.GUID != wintun.DefaultGUID || record.LUID == 0 || record.Boot == "" {
		log.Printf("invalid adapter identity history %q; recovering without historical LUID", s.file.Path+".adapter")
		return 0, nil
	}
	if record.Boot != boot {
		return 0, nil
	}
	return record.LUID, nil
}

func (s *diskJournal) saveAdapterHistory(boot string, luid uint64) (err error) {
	b, err := json.Marshal(adapterHistory{boot, wintun.DefaultGUID, luid})
	if err != nil {
		return err
	}
	path := s.file.Path + ".adapter"
	f, err := os.CreateTemp(filepath.Dir(path), ".adapter-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = s.sync(f)
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return s.replace(f.Name(), path)
}

func readMachineAdapterHistory(dir, boot string) (machineAdapterHistory, error) {
	path := filepath.Join(dir, "adapter-history.json")
	b, err := sharedfile.ReadFile(path, 8192)
	if os.IsNotExist(err) {
		return machineAdapterHistory{Boot: boot}, nil
	}
	if err != nil {
		return machineAdapterHistory{}, err
	}
	var raw machineAdapterHistory
	if len(b) > 8192 || json.Unmarshal(b, &raw) != nil || raw.Boot == "" {
		log.Printf("invalid machine adapter history %q; recovering with clean boot record", path)
		return machineAdapterHistory{Boot: boot}, nil
	}
	if raw.Boot != boot {
		return machineAdapterHistory{Boot: boot}, nil
	}
	clean := machineAdapterHistory{Boot: boot, Default: raw.Default}
	for _, entry := range raw.Legacy {
		parsed, err := windows.GUIDFromString(entry.GUID)
		if err != nil || entry.LUID == 0 || strings.EqualFold(parsed.String(), wintun.DefaultGUID) {
			continue
		}
		clean.Legacy = appendRetiredLegacy(clean.Legacy, retiredLegacyAdapter{GUID: parsed.String(), LUID: entry.LUID})
	}
	return clean, nil
}

func writeMachineAdapterHistory(dir string, record machineAdapterHistory) error {
	b, err := json.Marshal(record)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "adapter-history.json")
	f, err := os.CreateTemp(dir, ".adapter-history-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	return replaceJournal(f.Name(), path)
}

func appendRetiredLegacy(list []retiredLegacyAdapter, item retiredLegacyAdapter) []retiredLegacyAdapter {
	for _, existing := range list {
		if strings.EqualFold(existing.GUID, item.GUID) && existing.LUID == item.LUID {
			return list
		}
	}
	list = append(list, item)
	if len(list) > maxRetiredLegacyAdapters {
		list = list[len(list)-maxRetiredLegacyAdapters:]
	}
	return list
}

func isNetSwitchLegacyAlias(alias string) bool {
	if alias == "NetSwitch" {
		return true
	}
	const prefix = "NetSwitch "
	if !strings.HasPrefix(alias, prefix) {
		return false
	}
	rest := alias[len(prefix):]
	if len(rest) == 0 || len(rest) > 4 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] < '0' || rest[i] > '9' {
			return false
		}
	}
	return true
}

// RecordRetiredLegacyAdapter waits for any stopped 0.3.x NetSwitch Wintun
// adapter to finish asynchronous PnP and IPv4/IPv6 teardown, then records any
// lingering TIME_WAIT NDIS interface row for the current Windows boot inside
// the certified engine ownership directory under OwnershipLock.
func RecordRetiredLegacyAdapter(ctx context.Context) (retErr error) {
	if !Elevated() {
		return errors.New("recording retired legacy adapter requires elevation")
	}
	ownershipDir, release, err := acquireOwnershipLock(ctx)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, release()) }()

	boot, err := bootIdentity()
	if err != nil {
		return err
	}

	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for legacy NetSwitch adapter retirement: %w", err)
		}
		rows, err := nativeAdapterRows()
		if err != nil {
			return err
		}
		var candidates []retiredLegacyAdapter
		stillRetiring := false
		for _, row := range rows {
			if strings.EqualFold(row.guid, wintun.DefaultGUID) || !isNetSwitchLegacyAlias(row.alias) {
				continue
			}
			parsed, gErr := windows.GUIDFromString(row.guid)
			if gErr != nil || row.luid == 0 {
				return fmt.Errorf("unidentifiable legacy NetSwitch adapter row guid=%q luid=%d", row.guid, row.luid)
			}
			devPresent, pErr := presentWintunDevice(parsed.String())
			if pErr != nil {
				return pErr
			}
			if devPresent {
				stillRetiring = true
				break
			}
			for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
				ipErr := nativeIPInterface(row.luid, family)
				if ipErr == nil {
					stillRetiring = true
					break
				}
				if !errors.Is(ipErr, windows.ERROR_NOT_FOUND) && !errors.Is(ipErr, windows.ERROR_FILE_NOT_FOUND) {
					return ipErr
				}
			}
			if stillRetiring {
				break
			}
			candidates = append(candidates, retiredLegacyAdapter{GUID: parsed.String(), LUID: row.luid})
		}
		if !stillRetiring {
			if len(candidates) == 0 {
				return nil
			}
			mh, err := readMachineAdapterHistory(ownershipDir, boot)
			if err != nil {
				return err
			}
			before := len(mh.Legacy)
			for _, c := range candidates {
				mh.Legacy = appendRetiredLegacy(mh.Legacy, c)
			}
			if len(mh.Legacy) != before {
				if err := writeMachineAdapterHistory(ownershipDir, mh); err != nil {
					return err
				}
			}
			return nil
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("wait for legacy NetSwitch adapter retirement: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
