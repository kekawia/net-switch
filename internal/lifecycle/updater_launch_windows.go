package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/kekawia/net-switch/internal/platform/winapi"
	"github.com/kekawia/net-switch/internal/updates"
	"golang.org/x/sys/windows"
)

// startUpdateProcess never inherits handles. Installer children enter their job
// atomically at creation. The detached updater starts running and also verifies
// its own membership before doing work, so parent death cannot strand it suspended.
func startUpdateProcess(executable string, args []string, job windows.Handle) (windows.ProcessInformation, error) {
	var process windows.ProcessInformation
	if !filepath.IsAbs(executable) {
		return process, errors.New("updater executable must be absolute")
	}
	app, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return process, err
	}
	command, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{executable}, args...)))
	if err != nil {
		return process, err
	}
	directory, err := windows.UTF16PtrFromString(filepath.Dir(executable))
	if err != nil {
		return process, err
	}
	flags := uint32(windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS | windows.CREATE_UNICODE_ENVIRONMENT)
	startup := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}}
	if job == 0 {
		inside, err := winapi.ProcessInJob(windows.CurrentProcess(), 0)
		if err != nil {
			return process, err
		}
		if inside {
			flags |= windows.CREATE_BREAKAWAY_FROM_JOB
		}
	} else {
		attributes, err := windows.NewProcThreadAttributeList(1)
		if err != nil {
			return process, err
		}
		defer attributes.Delete()
		jobs := []windows.Handle{job}
		// PROC_THREAD_ATTRIBUTE_JOB_LIST, already used by the native child and
		// registrar launchers. Update retains the backing pointer until creation.
		if err := attributes.Update(0x0002000D, unsafe.Pointer(&jobs[0]), unsafe.Sizeof(jobs[0])); err != nil {
			return process, err
		}
		startup.Cb = uint32(unsafe.Sizeof(startup))
		startup.ProcThreadAttributeList = attributes.List()
		flags |= windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT
	}
	if err := windows.CreateProcess(app, command, nil, nil, false, flags, nil, directory, &startup.StartupInfo, &process); err != nil {
		return process, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = windows.TerminateProcess(process.Process, 1)
			_, _ = windows.WaitForSingleObject(process.Process, 10000)
			windows.CloseHandle(process.Thread)
			windows.CloseHandle(process.Process)
		}
	}()
	inside, err := winapi.ProcessInJob(process.Process, job)
	if err != nil {
		return windows.ProcessInformation{}, err
	}
	if inside != (job != 0) {
		return windows.ProcessInformation{}, fmt.Errorf("update process has unexpected job membership: inside=%t assigned_job=%t pid=%d", inside, job != 0, process.ProcessId)
	}
	if job != 0 {
		previous, err := windows.ResumeThread(process.Thread)
		if err != nil {
			return windows.ProcessInformation{}, err
		}
		if previous != 1 {
			return windows.ProcessInformation{}, fmt.Errorf("unexpected installer suspend count %d", previous)
		}
	}
	windows.CloseHandle(process.Thread)
	process.Thread = 0
	ok = true
	return process, nil
}

func launchDetachedUpdater(executable string, args []string) (uint32, error) {
	process, err := startUpdateProcess(executable, args, 0)
	if err != nil {
		return 0, err
	}
	return process.ProcessId, windows.CloseHandle(process.Process)
}

// The updater is not in this job. Closing it on crash/timeout also stops Inno's
// temporary setup helper, so rollback cannot race a surviving installer child.
func runUpdateInstaller(ctx context.Context, executable string, args []string) (uint32, error) {
	job, err := winapi.NewKillOnCloseJob()
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(job)
	process, err := startUpdateProcess(executable, args, job)
	if err != nil {
		return 0, err
	}
	defer func() {
		if process.Process != 0 {
			windows.CloseHandle(process.Process)
		}
	}()
	stop := func(cause error) (uint32, error) {
		killErr := windows.TerminateJobObject(job, 1)
		if process.Process != 0 {
			windows.CloseHandle(process.Process)
		}
		process.Process = 0
		wait, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := waitInstallerJob(wait, job); err != nil {
			return 0, errors.Join(cause, killErr, err, updates.ErrInstallerStillRunning)
		}
		return 0, errors.Join(cause, killErr)
	}
	for {
		status, err := windows.WaitForSingleObject(process.Process, 50)
		if err != nil {
			return stop(err)
		}
		if status == windows.WAIT_OBJECT_0 {
			var code uint32
			if err := windows.GetExitCodeProcess(process.Process, &code); err != nil {
				return stop(err)
			}
			windows.CloseHandle(process.Process)
			process.Process = 0
			if err := waitInstallerJob(ctx, job); err != nil {
				return stop(err)
			}
			return code, nil
		}
		if ctx.Err() != nil {
			return stop(ctx.Err())
		}
	}
}

func waitInstallerJob(ctx context.Context, job windows.Handle) error {
	for {
		var accounting struct {
			TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime int64
			PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
		}
		if err := winapi.QueryJobInformation(job, windows.JobObjectBasicAccountingInformation, &accounting); err != nil {
			return err
		}
		if accounting.ActiveProcesses == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}
