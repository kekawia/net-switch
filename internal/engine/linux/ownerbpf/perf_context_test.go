package ownerbpf

import (
	"reflect"
	"testing"
)

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

func TestOnlineCPUs(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  []int
	}{
		{"0-2,4,7-8", []int{0, 1, 2, 4, 7, 8}},
		{"0-3\n", []int{0, 1, 2, 3}},
		{"0\n", []int{0}},
		{"0-1,4-7\n", []int{0, 1, 4, 5, 6, 7}},
	} {
		got, err := onlineCPUs(tc.input)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("onlineCPUs(%q) = %v, %v; want %v", tc.input, got, err, tc.want)
		}
	}
	for _, input := range []string{"", "\n", " \t\n", "-1", "2-1", "0,0", "0-512", "0-512\n", "1-2-3", "0,,1\n", "0-1,\n", "0 - 3\n", "garbage"} {
		if _, err := onlineCPUs(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}
