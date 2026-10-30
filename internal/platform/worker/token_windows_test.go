package worker

import (
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWorkerRestrictingSIDs(t *testing.T) {
	var source windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &source); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	for _, test := range []struct {
		name           string
		admin, network bool
		want           []string
	}{
		{"read", false, false, []string{"S-1-5-12"}},
		{"probe", false, true, []string{"S-1-5-12", "S-1-5-32-545"}},
		{"outside", true, false, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := workerTokenForMode(source, test.admin, test.network)
			if err != nil {
				t.Fatal(err)
			}
			defer token.Close()
			var size uint32
			_ = windows.GetTokenInformation(token, windows.TokenRestrictedSids, nil, 0, &size)
			// An empty TOKEN_GROUPS can be smaller than Go's struct, which
			// includes its first flexible-array element. Keep the typed view
			// inside the allocation even for the unrestricted admin token.
			buffer := make([]uint64, (max(uintptr(size), unsafe.Sizeof(windows.Tokengroups{}))+7)/8)
			if err := windows.GetTokenInformation(token, windows.TokenRestrictedSids, (*byte)(unsafe.Pointer(&buffer[0])), size, &size); err != nil {
				t.Fatal(err)
			}
			groups := (*windows.Tokengroups)(unsafe.Pointer(&buffer[0])).AllGroups()
			var got []string
			for _, group := range groups {
				got = append(got, group.Sid.String())
			}
			if !slices.Equal(got, test.want) {
				t.Fatalf("restricting SIDs: %v, want %v", got, test.want)
			}
		})
	}
}
