//go:build linux

package ownerbpf

import (
	"reflect"
	"testing"
)

func TestOnlineCPUs(t *testing.T) {
	got, err := onlineCPUs("0-2,4,7-8")
	if err != nil || !reflect.DeepEqual(got, []int{0, 1, 2, 4, 7, 8}) {
		t.Fatalf("%v %v", got, err)
	}
	for _, input := range []string{"", "-1", "2-1", "0,0", "0-512", "1-2-3", "garbage"} {
		if _, err := onlineCPUs(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}
