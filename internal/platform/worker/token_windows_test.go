package worker

import (
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
		want           string
	}{
		{"read", false, false, "S-1-0-0"},
		{"probe", false, true, "S-1-5-32-545"},
		{"outside", true, false, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := workerTokenForMode(source, test.admin, test.network)
			if err != nil {
				t.Fatal(err)
			}
			defer token.Close()
			var size uint32
			_ = windows.GetTokenInformation(token, windows.TokenRestrictedSids, nil, 0, &size)
			buffer := make([]uint64, (size+7)/8)
			if err := windows.GetTokenInformation(token, windows.TokenRestrictedSids, (*byte)(unsafe.Pointer(&buffer[0])), size, &size); err != nil {
				t.Fatal(err)
			}
			groups := (*windows.Tokengroups)(unsafe.Pointer(&buffer[0])).AllGroups()
			if test.want == "" {
				if len(groups) != 0 {
					t.Fatal("administrative worker unexpectedly restricted", groups)
				}
			} else if len(groups) != 1 || groups[0].Sid.String() != test.want {
				t.Fatalf("restricting SIDs: %v, want only %s", groups, test.want)
			}
		})
	}
}
