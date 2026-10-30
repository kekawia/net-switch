package winplatform

import (
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The retained-handle regression models an ordinary Medium user with an
// explicit WRITE_DAC grant. It must not borrow the product's read sandbox:
// doing so prevents the attack precondition and stops testing quarantine.
type metadataAttacker struct {
	cmd            *exec.Cmd
	input          io.WriteCloser
	output, errors io.ReadCloser
	wait           sync.Once
	waitErr        error
}

func (p *metadataAttacker) Input() io.WriteCloser { return p.input }
func (p *metadataAttacker) Output() io.ReadCloser { return p.output }
func (p *metadataAttacker) Errors() io.ReadCloser { return p.errors }
func (p *metadataAttacker) Kill() error           { return p.cmd.Process.Kill() }
func (p *metadataAttacker) Wait() error {
	p.wait.Do(func() { p.waitErr = p.cmd.Wait() })
	return p.waitErr
}
func (p *metadataAttacker) Close() error {
	_ = p.Kill()
	_ = p.Wait()
	_ = p.input.Close()
	_ = p.output.Close()
	return p.errors.Close()
}
func startMetadataAttacker(exe string) (_ *metadataAttacker, err error) {
	var source, token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY|windows.TOKEN_ADJUST_DEFAULT, &source); err != nil {
		return nil, err
	}
	defer source.Close()
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	disabled := windows.SIDAndAttributes{Sid: admin}
	ok, _, callErr := windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken").Call(uintptr(source), 1, 1, uintptr(unsafe.Pointer(&disabled)), 0, 0, 0, 0, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return nil, callErr
	}
	defer token.Close()
	medium, err := windows.CreateWellKnownSid(windows.WinMediumLabelSid)
	if err != nil {
		return nil, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(token, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), label.Size()); err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "worker", "acl-proof")
	cmd.SysProcAttr = &syscall.SysProcAttr{Token: syscall.Token(token), CreationFlags: windows.DETACHED_PROCESS}
	p := &metadataAttacker{cmd: cmd}
	defer func() {
		if err != nil {
			if p.input != nil {
				p.input.Close()
			}
			if p.output != nil {
				p.output.Close()
			}
			if p.errors != nil {
				p.errors.Close()
			}
		}
	}()
	if p.input, err = cmd.StdinPipe(); err != nil {
		return nil, err
	}
	if p.output, err = cmd.StdoutPipe(); err != nil {
		return nil, err
	}
	if p.errors, err = cmd.StderrPipe(); err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("start ordinary Medium attacker: %w", err)
	}
	return p, nil
}
