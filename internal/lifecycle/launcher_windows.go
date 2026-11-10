package lifecycle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/service"
	"github.com/AyoubAchour/net-switch/internal/wintrust"
	"golang.org/x/sys/windows"
)

// MaybeDelegateVersionedDesktop forwards {app}\netswitch-desktop.exe to
// {app}\<current>\netswitch-desktop.exe when a versioned installation marker is
// present alongside the top-level launcher. Single-folder installations without
// a sibling "current" file run directly in the current process.
func MaybeDelegateVersionedDesktop(args []string) (bool, int, error) {
	exe, err := os.Executable()
	if err != nil {
		return false, 0, err
	}
	exe = filepath.Clean(exe)
	dir := filepath.Dir(exe)
	if isVersionedAppSubdir(filepath.Base(dir)) {
		return false, 0, nil
	}
	markerPath := filepath.Join(dir, "current")
	raw, exists, err := readNoFollowMarker(markerPath)
	if err != nil {
		return false, 0, err
	}
	if !exists {
		return false, 0, nil
	}
	if err := wintrust.Path(markerPath, false); err != nil {
		return false, 0, err
	}
	sub, err := ParseCurrentMarker(raw)
	if err != nil {
		return false, 0, err
	}
	targetDir := filepath.Join(dir, sub)
	if err := service.CheckInstallation(targetDir); err != nil {
		return false, 0, err
	}
	targetExe := filepath.Join(targetDir, filepath.Base(exe))
	if synchronousLauncherInvocation(args) {
		cmd := exec.Command(targetExe, args...)
		cmd.Dir = targetDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return true, exitErr.ExitCode(), nil
			}
			return true, 1, err
		}
		return true, 0, nil
	}
	appName, err := windows.UTF16PtrFromString(targetExe)
	if err != nil {
		return false, 0, err
	}
	cmdLine, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{targetExe}, args...)))
	if err != nil {
		return false, 0, err
	}
	workDir, err := windows.UTF16PtrFromString(targetDir)
	if err != nil {
		return false, 0, err
	}
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(appName, cmdLine, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, nil, workDir, &si, &pi); err != nil {
		return false, 0, fmt.Errorf("start versioned desktop %s: %w", targetExe, err)
	}
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)
	return true, 0, nil
}

func readNoFollowMarker(path string) ([]byte, bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks != 1 {
		return nil, false, fmt.Errorf("current version marker is not a plain single-link file: %s", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, 256))
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
