//go:build windows

package winengine

import (
	"errors"
	"maps"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWFPStatusUsesDocumentedDWORD(t *testing.T) {
	for _, code := range []windows.Handle{windows.FWP_E_FILTER_NOT_FOUND, windows.FWP_E_SUBLAYER_NOT_FOUND} {
		for _, raw := range []uintptr{uintptr(code), uintptr(code) | 0xffffffff00000000} {
			err := wfpStatus("test", raw)
			if !wfpMissing(err) || !errors.Is(err, windows.Errno(code)) {
				t.Fatalf("native status 0x%x did not preserve the missing-object code: %v", raw, err)
			}
		}
	}
	if wfpStatus("test", 0) != nil {
		t.Fatal("success returned an error")
	}
	if wfpMissing(wfpStatus("test", uintptr(windows.ERROR_ACCESS_DENIED))) {
		t.Fatal("access denial was mistaken for an absent filter")
	}
}

func TestWFPNativeMissingObjects(t *testing.T) {
	hosted(t)
	h, err := openWFP()
	if err != nil {
		t.Fatal(err)
	}
	defer wfpCall("FwpmEngineClose0", uintptr(h))
	key, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"FwpmSubLayerGetByKey0", "FwpmFilterGetByKey0"} {
		var row unsafe.Pointer
		err := wfpCall(operation, uintptr(h), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&row)))
		if !wfpMissing(err) || row != nil {
			t.Fatalf("%s: expected an absent random GUID without an object: %p %v", operation, row, err)
		}
		t.Logf("native absent-object status: %v", err)
	}
}

func TestWFPDocumentedLayouts(t *testing.T) {
	if unsafe.Sizeof(wfpValue{}) != 16 || unsafe.Sizeof(wfpCondition{}) != 40 ||
		unsafe.Sizeof(wfpFilter{}) != 200 || unsafe.Sizeof(wfpSubLayer{}) != 72 ||
		unsafe.Offsetof(wfpFilter{}.Conditions) != 120 || unsafe.Offsetof(wfpFilter{}.Action) != 128 ||
		unsafe.Offsetof(wfpFilter{}.Context) != 152 || unsafe.Offsetof(wfpFilter{}.ID) != 176 {
		t.Fatal("WFP ABI does not match the supported 64-bit Windows SDK layout")
	}
}

func TestWFPAllowsOnlyOwnedInboundErrorTypes(t *testing.T) {
	const owner = "0123456789abcdef0123456789abcdef"
	if err := validateWFP("wfp-sublayer", wfpLayerFingerprint(owner)); err != nil {
		t.Fatal(err)
	}
	for _, creation := range wfpFilterFingerprints(owner, 123456, 42) {
		fp := creation.Fingerprint
		if err := validateWFP(creation.Kind, fp); err != nil {
			t.Fatal(err)
		}
		input := makeWFPFilter(fp)
		if !matchesWFPFilter(&input.row, fp) {
			t.Fatal("our filter did not match its complete fingerprint")
		}
		input.conditions[0].Field = wfpICMPType
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("filter without its arriving-interface condition was accepted")
		}
		input = makeWFPFilter(fp)
		input.luid++
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("filter on another interface was adopted")
		}
		input = makeWFPFilter(fp)
		input.conditions[1].Value.Value = 8
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("ICMP echo permission was accepted")
		}
		input = makeWFPFilter(fp)
		input.marker[0] ^= 1
		if matchesWFPFilter(&input.row, fp) {
			t.Fatal("another owner's rule was adopted")
		}
		for key, value := range map[string]string{"direction": "outbound", "type": "8", "action": "block", "flags": "0", "luid": "0"} {
			changed := maps.Clone(fp)
			changed[key] = value
			if err := validateWFP(creation.Kind, changed); err == nil {
				t.Fatalf("out-of-scope journal fingerprint accepted: %s=%s", key, value)
			}
		}
	}
}

func TestWFPSubLayerOwnershipAndWeightNormalization(t *testing.T) {
	const owner = "0123456789abcdef0123456789abcdef"
	fp := wfpLayerFingerprint(owner)
	display, blob, marker := wfpMetadata(owner)
	defer func() { _ = marker }()

	makeSubLayer := func(weight uint16) wfpSubLayer {
		return wfpSubLayer{
			Key:     mustGUID(wfpSubLayerKey),
			Display: display,
			Flags:   1,
			Data:    blob,
			Weight:  weight,
		}
	}

	// BFE readback weight normalized alongside WireGuard/WinDivert 0xFFFF sublayers
	// remains owned and valid above wfpMinSubLayerWeight.
	for _, w := range []uint16{65535, 65534, 65515, wfpMinSubLayerWeight} {
		row := makeSubLayer(w)
		if !matchesWFPSubLayer(&row, fp) {
			t.Fatalf("owned persistent sublayer at weight %d failed ownership check", w)
		}
		if row.Weight < wfpMinSubLayerWeight {
			t.Fatalf("weight %d unexpectedly below minimum %d", row.Weight, wfpMinSubLayerWeight)
		}
	}

	// Demoted owned sublayer (< wfpMinSubLayerWeight, e.g. 0x8000 universal tier)
	// still matches ownership so recovery/cleanup removes it instead of stranding
	// it in BFE, while live monitoring rejects row.Weight < wfpMinSubLayerWeight.
	demoted := makeSubLayer(0x8000)
	if !matchesWFPSubLayer(&demoted, fp) {
		t.Fatal("demoted owned sublayer must remain owned so cleanup deletes it")
	}
	if demoted.Weight >= wfpMinSubLayerWeight {
		t.Fatalf("0x8000 must be below wfpMinSubLayerWeight (0x%x)", wfpMinSubLayerWeight)
	}

	nonPersistent := makeSubLayer(65535)
	nonPersistent.Flags = 0
	if matchesWFPSubLayer(&nonPersistent, fp) {
		t.Fatal("non-persistent dynamic sublayer was adopted")
	}

	providerGUID := mustGUID("{11111111-2222-3333-4444-555555555555}")
	providerOwned := makeSubLayer(65535)
	providerOwned.Provider = &providerGUID
	if matchesWFPSubLayer(&providerOwned, fp) {
		t.Fatal("provider-associated sublayer was adopted")
	}

	otherDisplay, otherBlob, otherMarker := wfpMetadata("fedcba9876543210fedcba9876543210")
	defer func() { _ = otherMarker }()
	foreignOwner := makeSubLayer(65535)
	foreignOwner.Display = otherDisplay
	foreignOwner.Data = otherBlob
	if matchesWFPSubLayer(&foreignOwner, fp) {
		t.Fatal("another owner's sublayer was adopted")
	}
}
