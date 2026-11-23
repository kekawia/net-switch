//go:build windows

package lifecycle

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func setTestPriority(t *testing.T, class uint32) {
	t.Helper()
	if err := windows.SetPriorityClass(windows.CurrentProcess(), class); err != nil {
		t.Fatal(err)
	}
}

func TestServicePriorityRaisesNormalToAboveNormal(t *testing.T) {
	setTestPriority(t, windows.NORMAL_PRIORITY_CLASS)
	t.Cleanup(func() { setTestPriority(t, windows.NORMAL_PRIORITY_CLASS) })
	message, err := raiseServicePriority()
	if err != nil {
		t.Fatal(err)
	}
	class, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	if class != windows.ABOVE_NORMAL_PRIORITY_CLASS || message != "process priority: above normal" {
		t.Fatalf("class 0x%x, message %q", class, message)
	}
}

// An administrator's explicit choice is kept, as Linux keeps an explicit nice.
func TestServicePriorityKeepsAnExplicitClass(t *testing.T) {
	setTestPriority(t, windows.BELOW_NORMAL_PRIORITY_CLASS)
	t.Cleanup(func() { setTestPriority(t, windows.NORMAL_PRIORITY_CLASS) })
	message, err := raiseServicePriority()
	if err != nil {
		t.Fatal(err)
	}
	class, err := windows.GetPriorityClass(windows.CurrentProcess())
	if err != nil {
		t.Fatal(err)
	}
	if class != windows.BELOW_NORMAL_PRIORITY_CLASS || !strings.Contains(message, "keeping explicit class") {
		t.Fatalf("explicit class replaced: class 0x%x, message %q", class, message)
	}
}
