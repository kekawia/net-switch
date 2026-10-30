package worker

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/AyoubAchour/net-switch/internal/platform/winapi"
	"golang.org/x/sys/windows"
)

type process struct {
	handle, job   windows.Handle
	output, input *os.File
	errors        *os.File
	wait          sync.Once
	waitErr       error
	exited        bool
	close         sync.Once
	fence         *networkFence
	image         *workerImage
	closeErr      error
}

func (p *process) Input() io.WriteCloser { return p.input }
func (p *process) Output() io.ReadCloser { return p.output }
func (p *process) Errors() io.ReadCloser { return p.errors }
func (p *process) Kill() error           { return windows.TerminateJobObject(p.job, 1) }
func (p *process) Wait() error {
	p.wait.Do(func() {
		var state uint32
		state, p.waitErr = windows.WaitForSingleObject(p.handle, windows.INFINITE)
		p.exited = p.waitErr == nil && state == windows.WAIT_OBJECT_0
		if p.waitErr == nil {
			var code uint32
			p.waitErr = windows.GetExitCodeProcess(p.handle, &code)
			if code != 0 {
				p.waitErr = fmt.Errorf("worker exited %d (0x%08X)", code, code)
				if code == 0xc0000142 {
					p.waitErr = fmt.Errorf("%w: STATUS_DLL_INIT_FAILED during Windows process initialization", p.waitErr)
				}
			}
		}
	})
	return p.waitErr
}
func (p *process) Close() error {
	p.close.Do(func() {
		_ = p.Kill()
		_ = p.Wait()
		p.input.Close()
		p.output.Close()
		p.errors.Close()
		windows.CloseHandle(p.handle)
		windows.CloseHandle(p.job)
		if !p.exited {
			p.closeErr = fmt.Errorf("worker termination was not confirmed; retaining network fence and image: %v", p.waitErr)
			if p.fence != nil && p.fence.engine != 0 {
				p.closeErr = errors.Join(p.closeErr, networkCall("FwpmEngineClose0", uintptr(p.fence.engine)))
				p.fence.engine = 0
			}
			log.Print(p.closeErr)
			return
		}
		if p.image != nil {
			p.closeErr = p.image.removeExecutable()
		}
		if p.fence != nil && p.closeErr == nil {
			p.closeErr = p.fence.close()
		}
		if p.image != nil && p.closeErr == nil {
			p.closeErr = p.image.removeFiles()
		}
		if p.closeErr != nil && p.fence != nil && p.fence.engine != 0 {
			// Static rules stay active without leaking the parent's RPC handle.
			p.closeErr = errors.Join(p.closeErr, networkCall("FwpmEngineClose0", uintptr(p.fence.engine)))
			p.fence.engine = 0
		}
		if p.closeErr != nil {
			log.Printf("worker cleanup: %v", p.closeErr)
		}
	})
	return p.closeErr
}

const workerUILimits = windows.JOB_OBJECT_UILIMIT_DESKTOP | windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
	windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
	windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD |
	windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD

// Reads use a Medium-integrity token with Administrators deny-only. Writes and
// outside (which enables TCP counters) retain admin access with privileges
// stripped. Both enter a bounded worker-only job before they can execute.
func Start(executable string, args []string) (Process, error) {
	// No worker needs a console. CREATE_NO_WINDOW still enters hidden-console
	// initialization for console-subsystem binaries, which fails with a lowered
	// token on hosted Windows (0xC0000142). DETACHED_PROCESS avoids that path;
	// the only inherited I/O remains our three explicit pipes. GUI-subsystem
	// builds and USER32/GDI icon extraction work with the same token/job limits.
	return start(executable, args, nil, windows.DETACHED_PROCESS, workerUILimits)
}

// The explicit startup inputs let hosted tests distinguish loader, desktop and
// job failures. Production callers always go through Start's fixed policy.
func start(executable string, args []string, desktop *uint16, creationFlags, uiLimits uint32) (Process, error) {
	if !filepath.IsAbs(executable) || len(args) < 2 || args[0] != "worker" {
		return nil, fmt.Errorf("worker launcher requires its absolute executable and a worker mode")
	}
	mode := workerMode(args)
	admin := adminWorker(args)
	network := mode == "probe" || mode == "line-check"
	var fence *networkFence
	var image *workerImage
	fenceIntent := false
	var err error
	if !admin && !network {
		imageRecovery.Lock()
		if err := recoverWorkerImages(); err != nil {
			log.Printf("worker image recovery: %v", err)
		}
		imageRecovery.Unlock()
		image, err = newWorkerImage(executable)
		if err != nil {
			return nil, fmt.Errorf("prepare %s worker image: %w", mode, err)
		}
		executable = image.executable
	}
	policy := processPolicy{}
	if image != nil {
		policy.beforeResume = func(child windows.Handle) error {
			pid, err := windows.GetProcessId(child)
			if err != nil {
				return err
			}
			created, err := processCreated(child)
			if err != nil {
				return err
			}
			if err = writeImageRecord(filepath.Join(image.directory, "child.json"), imageOwner{pid, created}); err != nil {
				return err
			}
			fenceIntent = true
			fence, err = fenceWorkerNetwork(image)
			return err
		}
	}
	p, err := startWithToken(executable, args, desktop, creationFlags, uiLimits, func(token windows.Token) (windows.Token, error) {
		if admin {
			return workerTokenForMode(token, true, false)
		}
		return workerTokenWithSIDs(token, false, workerReadSIDs(mode))
	}, policy)
	if err != nil {
		if fence != nil {
			err = errors.Join(err, fence.close())
		}
		if image != nil {
			var cleanup error
			if fenceIntent {
				cleanup = removeImageFence(image)
			}
			if cleanup != nil {
				err = errors.Join(err, cleanup)
			} else {
				err = errors.Join(err, image.removeFiles())
			}
		}
		return nil, err
	}
	p.(*process).fence = fence
	p.(*process).image = image
	return p, nil
}

var imageRecovery sync.Mutex

type processPolicy struct {
	beforeResume func(windows.Handle) error
}

// Token injection is private to this package's hosted compatibility tests.
// Start and start always select the production policy above.
func startWithToken(executable string, args []string, desktop *uint16, creationFlags, uiLimits uint32, makeToken func(windows.Token) (windows.Token, error), policies ...processPolicy) (Process, error) {
	if !filepath.IsAbs(executable) || len(args) < 2 || args[0] != "worker" {
		return nil, fmt.Errorf("worker launcher requires its absolute executable and a worker mode")
	}
	var policy processPolicy
	if len(policies) > 0 {
		policy = policies[0]
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			windows.CloseHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags:         windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY,
			ActiveProcessLimit: 1,
		},
		ProcessMemoryLimit: 256 * 1024 * 1024,
	}
	if err = winapi.SetJobInformation(job, windows.JobObjectExtendedLimitInformation, &limits); err != nil {
		return nil, err
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: uiLimits}
	if err := winapi.SetJobInformation(job, windows.JobObjectBasicUIRestrictions, &ui); err != nil {
		return nil, fmt.Errorf("limit worker UI access: %w", err)
	}
	var token windows.Token
	if err = windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT, &token); err != nil {
		return nil, err
	}
	defer token.Close()
	restricted, err := makeToken(token)
	if err != nil {
		return nil, err
	}
	defer restricted.Close()
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer writer.Close()
	defer func() {
		if !ok {
			reader.Close()
		}
	}()
	stdin, hold, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer stdin.Close()
	defer func() {
		if !ok {
			hold.Close()
		}
	}()
	errorReader, errorWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer errorWriter.Close()
	defer func() {
		if !ok {
			errorReader.Close()
		}
	}()
	// stderr has its own pipe, including when Control has no console. Duplicate only these three
	// handles and use an explicit inheritance list, so jobs/tokens never leak.
	source := []windows.Handle{windows.Handle(stdin.Fd()), windows.Handle(writer.Fd()), windows.Handle(errorWriter.Fd())}
	handles := make([]windows.Handle, 3)
	for i, h := range source {
		if err := windows.DuplicateHandle(windows.CurrentProcess(), h, windows.CurrentProcess(), &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			for _, h := range handles {
				if h != 0 {
					windows.CloseHandle(h)
				}
			}
			return nil, err
		}
	}
	defer func() {
		for _, h := range handles {
			windows.CloseHandle(h)
		}
	}()
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return nil, err
	}
	jobRef := new(windows.Handle)
	*jobRef = job
	defer func() { attrs.Delete(); runtime.KeepAlive(jobRef) }()
	// Assign atomically at creation: parent death cannot strand a suspended
	// process outside the kill-on-close job or its orphan-recovery record.
	if err := attrs.Update(0x2000D, unsafe.Pointer(jobRef), unsafe.Sizeof(*jobRef)); err != nil {
		return nil, fmt.Errorf("worker job list: %w", err)
	}
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), uintptr(len(handles))*unsafe.Sizeof(handles[0])); err != nil {
		return nil, err
	}
	si := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2]}, ProcThreadAttributeList: attrs.List()}
	si.Desktop = desktop
	quoted := []string{windows.EscapeArg(executable)}
	for _, a := range args {
		quoted = append(quoted, windows.EscapeArg(a))
	}
	app, err := windows.UTF16PtrFromString(executable)
	if err != nil {
		return nil, err
	}
	cmd, err := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	if err != nil {
		return nil, err
	}
	var pi windows.ProcessInformation
	if err = windows.CreateProcessAsUser(restricted, app, cmd, nil, nil, true, windows.CREATE_SUSPENDED|creationFlags|windows.EXTENDED_STARTUPINFO_PRESENT, nil, nil, &si.StartupInfo, &pi); err != nil {
		return nil, err
	}
	defer windows.CloseHandle(pi.Thread)
	if policy.beforeResume != nil {
		if err = policy.beforeResume(pi.Process); err != nil {
			windows.TerminateJobObject(job, 1)
			windows.WaitForSingleObject(pi.Process, windows.INFINITE)
			windows.CloseHandle(pi.Process)
			return nil, err
		}
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		windows.TerminateJobObject(job, 1)
		windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		windows.CloseHandle(pi.Process)
		return nil, err
	}
	ok = true
	return &process{handle: pi.Process, job: job, output: reader, input: hold, errors: errorReader}, nil
}

func workerToken(token windows.Token, administrative bool) (windows.Token, error) {
	return workerTokenForMode(token, administrative, false)
}

func workerReadSIDs(mode string) []string {
	sids := []string{"S-1-5-12"}
	if mode == "probe" || mode == "line-check" {
		sids = append(sids, "S-1-5-32-545")
	}
	if mode == "tcp-port-configuration" {
		sids = append(sids, "S-1-5-11")
	}
	return sids
}

func workerTokenForMode(token windows.Token, administrative, network bool) (windows.Token, error) {
	var sids []string
	if !administrative {
		sids = []string{"S-1-5-12"}
		if network {
			sids = append(sids, "S-1-5-32-545")
		}
	}
	return workerTokenWithSIDs(token, administrative, sids)
}

func workerTokenWithSIDs(token windows.Token, administrative bool, sids []string) (windows.Token, error) {
	return constructWorkerToken(token, administrative, sids, false)
}

func constructWorkerToken(token windows.Token, administrative bool, sids []string, disableSystemUser bool) (windows.Token, error) {
	var disabled []windows.SIDAndAttributes
	if !administrative {
		groups, err := token.GetTokenGroups()
		if err != nil {
			return 0, err
		}
		filtered, err := filteredTokenGroups(token)
		if err != nil {
			return 0, err
		}
		disabled, err = disabledWorkerGroups(groups.AllGroups(), filtered)
		if err != nil {
			return 0, err
		}
		user, err := token.GetTokenUser()
		if err != nil {
			return 0, err
		}
		if disableSystemUser && user.User.Sid.String() == "S-1-5-18" {
			disabled = append(disabled, windows.SIDAndAttributes{Sid: user.User.Sid})
		}
	}
	var disabledSIDs *windows.SIDAndAttributes
	if len(disabled) != 0 {
		disabledSIDs = &disabled[0]
	}
	var restricted windows.Token
	flags := uintptr(1) // DISABLE_MAX_PRIVILEGE
	var restricting *windows.SIDAndAttributes
	var restrictingCount uintptr
	var restrictions []windows.SIDAndAttributes
	if !administrative {
		// Preserve the normal identity for native reads; every write must also
		// pass this independent SID set, which never includes SYSTEM or admin.
		// WFP uses a private executable identity to enforce network denial.
		if len(sids) == 0 {
			return 0, fmt.Errorf("read worker requires restricting SIDs")
		}
		for _, text := range sids {
			sid, err := windows.StringToSid(text)
			if err != nil {
				return 0, err
			}
			restrictions = append(restrictions, windows.SIDAndAttributes{Sid: sid})
		}
		restricting = &restrictions[0]
		restrictingCount = uintptr(len(restrictions))
		flags |= 8 // WRITE_RESTRICTED (supported Windows versions)
	}
	proc := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	result, _, callErr := proc.Call(uintptr(token), flags, uintptr(len(disabled)), uintptr(unsafe.Pointer(disabledSIDs)), 0, 0, restrictingCount, uintptr(unsafe.Pointer(restricting)), uintptr(unsafe.Pointer(&restricted)))
	if result == 0 {
		return 0, fmt.Errorf("restrict worker token: %w", callErr)
	}
	if !administrative {
		if err := mediumIntegrity(restricted); err != nil {
			restricted.Close()
			return 0, err
		}
	}
	return restricted, nil
}

func filteredTokenGroups(token windows.Token) ([]windows.SIDAndAttributes, error) {
	var elevation, size uint32
	if err := windows.GetTokenInformation(token, windows.TokenElevationType, (*byte)(unsafe.Pointer(&elevation)), 4, &size); err != nil {
		return nil, fmt.Errorf("read worker elevation type: %w", err)
	}
	if elevation == 1 { // TokenElevationTypeDefault
		return nil, nil // No split token (SYSTEM, UAC disabled, batch logon).
	}
	filtered := token
	if elevation == 2 { // TokenElevationTypeFull
		linked, err := token.GetLinkedToken()
		if err != nil {
			return nil, fmt.Errorf("read worker linked token: %w", err)
		}
		defer linked.Close()
		filtered = linked
	} else if elevation != 3 { // TokenElevationTypeLimited
		return nil, fmt.Errorf("unexpected worker elevation type %d", elevation)
	}
	// An identification-level linked token is sufficient: query its groups,
	// never try to impersonate it or launch a process with it.
	groups, err := filtered.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("read filtered worker groups: %w", err)
	}
	return groups.AllGroups(), nil
}

func disabledWorkerGroups(groups, filtered []windows.SIDAndAttributes) ([]windows.SIDAndAttributes, error) {
	denyOnly := map[string]bool{}
	for _, group := range filtered {
		text := group.Sid.String()
		if text == "" {
			return nil, fmt.Errorf("could not read a filtered worker token group SID")
		}
		denyOnly[text] = group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0
	}
	var disabled []windows.SIDAndAttributes
	for _, group := range groups {
		text := group.Sid.String()
		if text == "" {
			return nil, fmt.Errorf("could not read a worker token group SID")
		}
		if denyOnly[text] || (filtered == nil && elevatedGroupText(text)) {
			disabled = append(disabled, windows.SIDAndAttributes{Sid: group.Sid})
		}
	}
	return disabled, nil
}

func mediumIntegrity(token windows.Token) error {
	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		return err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		return fmt.Errorf("lower worker integrity: %w", err)
	}
	return nil
}

// Fallback for tokens without a UAC pair: the 16 restricted RIDs in Microsoft's
// Windows Vista Application Development Requirements for UAC. Match the full SID namespace:
// a foreign-domain privileged group is just as powerful as the local domain's,
// while an unrelated SID with the same final RID must remain untouched.
func elevatedGroup(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	return elevatedGroupText(sid.String())
}

func elevatedGroupText(text string) bool {
	// The x/sys pointer-returning SID helpers round-trip Go-backed SID
	// addresses through uintptr, which fails checkptr. Canonical SID text
	// copies the value instead and keeps the exact authority/count checks.
	parts := strings.Split(text, "-")
	if len(parts) < 5 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" {
		return false
	}
	if len(parts) == 5 && parts[3] == "32" {
		switch parts[4] {
		case "544", "547", "548", "549", "550", "551", "554", "556", "569":
			return true
		}
	}
	if len(parts) == 8 && parts[3] == "21" {
		switch parts[7] {
		case "512", "516", "517", "518", "519", "520", "553":
			return true
		}
	}
	return false
}

func adminWorker(args []string) bool {
	mode := workerMode(args)
	switch mode {
	case "outside", "policy-set", "metrics-set", "metrics-restore", "protect-directory",
		"stop-process", "close-tcp", "autostart-set", "autostart-upgrade":
		return true
	}
	return false
}

func workerMode(args []string) string {
	mode := args[1]
	if mode == "query" && len(args) > 2 {
		mode = args[2]
	}
	return mode
}
