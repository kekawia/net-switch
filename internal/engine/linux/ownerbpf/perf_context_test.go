package ownerbpf

import "testing"

func TestConsumeContextLayoutRefusesMismatch(t *testing.T) {
	for _, good := range []string{
		"field:void * skbaddr;\toffset:8;\tsize:8;\tsigned:0;",
		"field:const void *skbaddr; offset:8; size:8; signed:0;",
	} {
		if err := checkConsumeFormat(good); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{"", "field:void *skbaddr; offset:16; size:8;", "field:void *skbaddr; offset:8; size:4;", "field:void *location; offset:8; size:8;"} {
		if checkConsumeFormat(bad) == nil {
			t.Fatalf("accepted incompatible context %q", bad)
		}
	}
}
