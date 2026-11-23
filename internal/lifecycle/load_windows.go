//go:build windows

package lifecycle

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32             = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes   = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStat = kernel32.NewProc("GlobalMemoryStatusEx")
)

type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

func filetime64(f windows.Filetime) uint64 {
	return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime)
}

func systemTimes() (idle, total uint64, err error) {
	var i, k, u windows.Filetime
	r, _, callErr := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	if r == 0 {
		return 0, 0, callErr
	}
	// Kernel time includes idle time.
	return filetime64(i), filetime64(k) + filetime64(u), nil
}

// systemLoad describes how busy the PC is right now, for logs written when a
// deadline is missed: CPU use over a quarter second and free memory. Microsoft
// added the same readings to SQL Server's lease-timeout logs, since a starved
// PC and a dead peer look alike from inside a timeout.
func systemLoad() string {
	cpu := "cpu unknown"
	if idle1, total1, err := systemTimes(); err == nil {
		time.Sleep(250 * time.Millisecond)
		if idle2, total2, err := systemTimes(); err == nil && total2 > total1 {
			busy := 100 * (1 - float64(idle2-idle1)/float64(total2-total1))
			cpu = fmt.Sprintf("cpu %.0f%%", max(0, min(100, busy)))
		}
	}
	m := memoryStatusEx{length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, _ := procGlobalMemoryStat.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return cpu + ", memory unknown"
	}
	return fmt.Sprintf("%s, %.1f GB of %.1f GB memory free", cpu, float64(m.availPhys)/(1<<30), float64(m.totalPhys)/(1<<30))
}
