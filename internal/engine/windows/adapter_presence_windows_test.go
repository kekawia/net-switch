//go:build windows

package winengine

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/AyoubAchour/net-switch/internal/journal"
	"github.com/AyoubAchour/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func TestUnreadableForeignWintunDoesNotBlockPresence(t *testing.T) {
	foreign := "{11111111-2222-3333-4444-555555555555}"
	for _, tc := range []struct {
		name, instance, id   string
		instanceErr, readErr error
		present, failed      bool
	}{
		{"foreign-key-unreadable", "SWD\\WINTUN\\" + foreign, "", nil, windows.ERROR_ACCESS_DENIED, false, false},
		{"foreign-value-missing", "swd\\wintun\\" + foreign, "", nil, windows.ERROR_FILE_NOT_FOUND, false, false},
		{"our-key-unreadable", "SWD\\WINTUN\\" + wintun.DefaultGUID, "", nil, windows.ERROR_ACCESS_DENIED, true, true},
		{"unknown-instance", "SWD\\WINTUN\\unexpected", "", nil, windows.ERROR_ACCESS_DENIED, true, true},
		{"suffix-not-proof", "SWD\\WINTUN\\" + foreign + "\\extra", "", nil, windows.ERROR_ACCESS_DENIED, true, true},
		{"unreadable-instance", "devinst:42", "", windows.ERROR_ACCESS_DENIED, windows.ERROR_ACCESS_DENIED, true, true},
		{"readable-ours-wins", "SWD\\WINTUN\\" + foreign, wintun.DefaultGUID, nil, nil, true, false},
		{"readable-foreign", "legacy-name", foreign, nil, nil, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			present, err := wintunDeviceMatches(wintun.DefaultGUID, tc.instance, tc.id, tc.instanceErr, tc.readErr)
			if present != tc.present || (err != nil) != tc.failed {
				t.Fatal(present, err)
			}
			if err != nil && !strings.Contains(err.Error(), strconv.Quote(tc.instance)) {
				t.Fatal("error omitted device identity", err)
			}
		})
	}
}

type disappearedAdapter struct{ *checkpointObjects }

func (d disappearedAdapter) Inspect(context.Context, journal.Fingerprint) (journal.Fingerprint, bool, error) {
	present, err := adapterPresent(wintun.DefaultGUID, "NetSwitch", 7, nil,
		func() (bool, error) { return false, nil }, func(uint64, uint16) error { return windows.ERROR_FILE_NOT_FOUND })
	return nil, present, err
}

func TestAdapterCreateAfterRowFullyDisappears(t *testing.T) {
	store := newDiskJournal(filepath.Join(t.TempDir(), "journal"))
	owned := &checkpointObjects{live: map[string]journal.Fingerprint{}}
	j := &journal.Journal{Store: store, Lock: checkpointLock{}, Kinds: map[string]journal.Object{"adapter": disappearedAdapter{owned}}}
	s, err := j.Open(context.Background(), "boot", "new-instance")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Create(context.Background(), "adapter", journal.Fingerprint{"name": "NetSwitch"}); err != nil {
		t.Fatal("stale historical LUID blocked create", err)
	}
	if len(owned.live) != 1 {
		t.Fatal("creation never reached platform driver")
	}
}

func TestAdapterPresenceUsesPnPAndBothIPFamilies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		luid   uint64
		rows   []adapterRow
		pnp    bool
		pnpErr error
		v4, v6 error
		want   bool
	}{
		{"lingering-down-row", 7, []adapterRow{{wintun.DefaultGUID, "NetSwitch", 7}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
		{"row-already-gone", 7, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
		{"row-gone-file-not-found", 7, nil, false, nil, windows.ERROR_FILE_NOT_FOUND, windows.ERROR_FILE_NOT_FOUND, false},
		{"mixed-family-missing", 7, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_FILE_NOT_FOUND, false},
		{"mixed-family-missing-reverse", 7, nil, false, nil, windows.ERROR_FILE_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
		{"present-pnp", 7, nil, true, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"present-v4", 7, nil, false, nil, nil, windows.ERROR_NOT_FOUND, true},
		{"present-v6", 7, nil, false, nil, windows.ERROR_NOT_FOUND, nil, true},
		{"pnp-error", 7, nil, false, windows.ERROR_ACCESS_DENIED, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"v4-error", 7, nil, false, nil, windows.ERROR_INVALID_PARAMETER, windows.ERROR_NOT_FOUND, true},
		{"v6-error", 7, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_ACCESS_DENIED, true},
		{"replacement-guid", 7, []adapterRow{{wintun.DefaultGUID, "NetSwitch", 8}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"replacement-alias", 7, []adapterRow{{"foreign", "NetSwitch", 7}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"unknown-luid", 0, []adapterRow{{wintun.DefaultGUID, "NetSwitch", 7}}, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, true},
		{"fresh-install", 0, nil, false, nil, windows.ERROR_NOT_FOUND, windows.ERROR_NOT_FOUND, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			present, err := adapterPresent(wintun.DefaultGUID, "NetSwitch", tc.luid, tc.rows,
				func() (bool, error) { return tc.pnp, tc.pnpErr }, func(luid uint64, family uint16) error {
					calls++
					if luid != tc.luid {
						t.Fatal("wrong interface identity")
					}
					if family == windows.AF_INET {
						return tc.v4
					}
					return tc.v6
				})
			if present != tc.want || (!present && err != nil) {
				t.Fatal(present, err)
			}
			if !present && tc.luid != 0 && calls != 2 {
				t.Fatal("did not confirm both families", calls)
			}
		})
	}
}

func TestAdapterHistorySurvivesProcessAndJournalCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal")
	s := newDiskJournal(path)
	if n, err := s.adapterHistory("boot"); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	if err := s.saveAdapterHistory("boot", 123); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(nil); err != nil {
		t.Fatal(err)
	}
	next := newDiskJournal(path)
	if n, err := next.adapterHistory("boot"); n != 123 || err != nil {
		t.Fatal(n, err)
	}
	if n, err := next.adapterHistory("next-boot"); n != 0 || err != nil {
		t.Fatal(n, err)
	}
	next.replace = func(string, string) error { return errors.New("publish failure") }
	if next.saveAdapterHistory("boot", 456) == nil {
		t.Fatal("ignored failed identity commit")
	}
	if n, err := s.adapterHistory("boot"); n != 123 || err != nil {
		t.Fatal("failed write replaced identity", n, err)
	}
}

func TestRetiredLegacyAdapterRowFilteringAndMachineHistory(t *testing.T) {
	legacyGUID := "{11111111-2222-3333-4444-555555555555}"
	unrecordedGUID := "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}"

	dir := t.TempDir()
	mh, err := readMachineAdapterHistory(dir, "boot-1")
	if err != nil || mh.Boot != "boot-1" || mh.Default != 0 || len(mh.Legacy) != 0 {
		t.Fatalf("unexpected empty machine history: %+v %v", mh, err)
	}
	mh.Default = 42
	mh.Legacy = appendRetiredLegacy(mh.Legacy, retiredLegacyAdapter{GUID: legacyGUID, LUID: 99})
	mh.Legacy = appendRetiredLegacy(mh.Legacy, retiredLegacyAdapter{GUID: legacyGUID, LUID: 99})
	if err := writeMachineAdapterHistory(dir, mh); err != nil {
		t.Fatal(err)
	}
	got, err := readMachineAdapterHistory(dir, "boot-1")
	if err != nil || got.Default != 42 || len(got.Legacy) != 1 || !strings.EqualFold(got.Legacy[0].GUID, legacyGUID) || got.Legacy[0].LUID != 99 {
		t.Fatalf("machine history roundtrip mismatch: %+v %v", got, err)
	}
	rotated, err := readMachineAdapterHistory(dir, "boot-2")
	if err != nil || rotated.Default != 0 || len(rotated.Legacy) != 0 {
		t.Fatalf("boot rotation retained stale adapter history: %+v %v", rotated, err)
	}

	// Retired legacy row with no PnP devnode and no IPv4/IPv6 IP interface is filtered.
	rows := []adapterRow{
		{guid: legacyGUID, alias: "NetSwitch", luid: 99},
		{guid: wintun.DefaultGUID, alias: "NetSwitch 1", luid: 42},
	}
	filtered, err := filterRetiredLegacyRows(rows, got.Legacy,
		func(string) (bool, error) { return false, nil },
		func(uint64, uint16) error { return windows.ERROR_NOT_FOUND })
	if err != nil || len(filtered) != 1 || filtered[0].luid != 42 {
		t.Fatalf("expected retired legacy row filtered and DefaultGUID retained: %+v %v", filtered, err)
	}
	present, err := adapterPresent(wintun.DefaultGUID, "NetSwitch", 42, filtered,
		func() (bool, error) { return false, nil },
		func(uint64, uint16) error { return windows.ERROR_NOT_FOUND })
	if present || err != nil {
		t.Fatalf("expected clean absence after retired legacy and DefaultGUID TIME_WAIT rows: present=%t err=%v", present, err)
	}

	// Restarted live 0.3.x adapter (reusing same GUID+LUID) with live PnP or IP must NOT be filtered and must fail closed.
	livePnP, err := filterRetiredLegacyRows(rows, got.Legacy,
		func(string) (bool, error) { return true, nil },
		func(uint64, uint16) error { return windows.ERROR_NOT_FOUND })
	if err != nil || len(livePnP) != 2 {
		t.Fatalf("live PnP legacy adapter was wrongly filtered: %+v %v", livePnP, err)
	}
	if p, pErr := adapterPresent(wintun.DefaultGUID, "NetSwitch", 42, livePnP, func() (bool, error) { return false, nil }, func(uint64, uint16) error { return windows.ERROR_NOT_FOUND }); !p || pErr == nil {
		t.Fatalf("live PnP legacy adapter did not fail closed: %t %v", p, pErr)
	}

	liveIP, err := filterRetiredLegacyRows(rows, got.Legacy,
		func(string) (bool, error) { return false, nil },
		func(uint64, uint16) error { return nil })
	if err != nil || len(liveIP) != 2 {
		t.Fatalf("live IP legacy adapter was wrongly filtered: %+v %v", liveIP, err)
	}

	// Unrecorded foreign NetSwitch row must NOT be filtered even when retired.
	unrecorded := []adapterRow{{guid: unrecordedGUID, alias: "NetSwitch", luid: 500}}
	keptUnrecorded, err := filterRetiredLegacyRows(unrecorded, got.Legacy,
		func(string) (bool, error) { return false, nil },
		func(uint64, uint16) error { return windows.ERROR_NOT_FOUND })
	if err != nil || len(keptUnrecorded) != 1 {
		t.Fatalf("unrecorded foreign row was wrongly filtered: %+v %v", keptUnrecorded, err)
	}
	if p, pErr := adapterPresent(wintun.DefaultGUID, "NetSwitch", 42, keptUnrecorded, func() (bool, error) { return false, nil }, func(uint64, uint16) error { return windows.ERROR_NOT_FOUND }); !p || pErr == nil {
		t.Fatalf("unrecorded foreign row did not fail closed: %t %v", p, pErr)
	}

	if !isNetSwitchLegacyAlias("NetSwitch") || !isNetSwitchLegacyAlias("NetSwitch 1") || isNetSwitchLegacyAlias("TestISP") || isNetSwitchLegacyAlias("NetSwitch abc") {
		t.Fatal("unexpected isNetSwitchLegacyAlias classification")
	}
}
