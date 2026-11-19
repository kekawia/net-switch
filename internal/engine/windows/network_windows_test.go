//go:build windows

package winengine

import (
	"errors"
	"fmt"
	"testing"

	"github.com/kekawia/net-switch/internal/wintun"
	"golang.org/x/sys/windows"
)

func TestCollectAdaptersSkipsVanishedInterfacesAndFailsOnUnexpectedErrors(t *testing.T) {
	mustUTF16 := func(s string) *uint16 {
		p, err := windows.UTF16PtrFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	wintunNode := windows.IpAdapterAddresses{
		IfType:       53,
		Luid:         100,
		FriendlyName: mustUTF16("NetSwitch"),
		OperStatus:   windows.IfOperStatusUp,
		Mtu:          9000,
	}
	loopbackNode := windows.IpAdapterAddresses{
		IfType:       24,
		Luid:         200,
		FriendlyName: mustUTF16("Loopback"),
		OperStatus:   windows.IfOperStatusUp,
		Next:         &wintunNode,
	}
	vanishedFileNotFound := windows.IpAdapterAddresses{
		IfType:       53,
		Luid:         300,
		FriendlyName: mustUTF16("wgclient"),
		OperStatus:   windows.IfOperStatusUp,
		Next:         &loopbackNode,
	}
	vanishedNotFound := windows.IpAdapterAddresses{
		IfType:       71,
		Luid:         301,
		FriendlyName: mustUTF16("Wi-Fi transient"),
		OperStatus:   windows.IfOperStatusDown,
		Next:         &vanishedFileNotFound,
	}
	ethernetNode := windows.IpAdapterAddresses{
		IfType:       6,
		Luid:         400,
		IfIndex:      12,
		FriendlyName: mustUTF16("Ethernet"),
		OperStatus:   windows.IfOperStatusUp,
		Mtu:          1500,
		Ipv4Metric:   10,
		Next:         &vanishedNotFound,
	}
	wifiNode := windows.IpAdapterAddresses{
		IfType:       71,
		Luid:         500,
		IfIndex:      15,
		FriendlyName: mustUTF16("Wi-Fi"),
		OperStatus:   windows.IfOperStatusUp,
		Mtu:          1500,
		Ipv4Metric:   25,
		Next:         &ethernetNode,
	}

	guids := map[uint64]struct {
		id  string
		err error
	}{
		100: {id: wintun.DefaultGUID},
		300: {err: fmt.Errorf("ConvertInterfaceLuidToGuid: %w", windows.ERROR_FILE_NOT_FOUND)},
		301: {err: fmt.Errorf("ConvertInterfaceLuidToGuid: %w", windows.ERROR_NOT_FOUND)},
		400: {id: "{11111111-1111-1111-1111-111111111111}"},
		500: {id: "{22222222-2222-2222-2222-222222222222}"},
	}
	lookup := func(luid uint64) (string, error) {
		entry, ok := guids[luid]
		if !ok {
			t.Fatalf("unexpected LUID lookup: %d", luid)
		}
		return entry.id, entry.err
	}

	adapters, err := collectAdapters(&wifiNode, map[uint64]bool{400: true, 500: true}, map[uint64]bool{}, lookup)
	if err != nil {
		t.Fatalf("collectAdapters failed on vanished adapters: %v", err)
	}
	if len(adapters) != 2 {
		t.Fatalf("got %d adapters (%+v), want 2", len(adapters), adapters)
	}
	if adapters[0].Alias != "Ethernet" || adapters[0].ID != "{11111111-1111-1111-1111-111111111111}" {
		t.Fatalf("unexpected first adapter: %+v", adapters[0])
	}
	if adapters[1].Alias != "Wi-Fi" || adapters[1].ID != "{22222222-2222-2222-2222-222222222222}" {
		t.Fatalf("unexpected second adapter: %+v", adapters[1])
	}

	// Non-missing errors must still fail closed rather than silently dropping adapters.
	unexpected := fmt.Errorf("ConvertInterfaceLuidToGuid: %w", windows.ERROR_ACCESS_DENIED)
	guids[300] = struct {
		id  string
		err error
	}{err: unexpected}
	_, err = collectAdapters(&wifiNode, map[uint64]bool{400: true}, map[uint64]bool{}, lookup)
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("got %v, want ERROR_ACCESS_DENIED", err)
	}
}
