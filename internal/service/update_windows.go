package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// StopForUpdate leaves both registrations available to the owner's desktop
// after a power loss. Deleting them would remove the recovery entry point.
func StopForUpdate(ctx context.Context) error {
	if err := stopUpdateControl(ctx); err != nil {
		return err
	}
	// Control requests a clean Engine shutdown; a lost Control connection also
	// expires Engine's lease. Never replace a binary while either writer lives.
	for {
		status, err := Query(Engine)
		if err != nil {
			return err
		}
		if status.Stopped {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s is still stopping: %w", Engine, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// A desktop activation can be in StartPending while the update startup guard
// exits. That guard has no writers and must not need to accept a Stop control
// before exiting. Reconcile the observed SCM state instead of treating an
// ordinary concurrent start/stop transition as an installer failure.
func stopUpdateControl(ctx context.Context) error {
	s, err := open(Control, windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	for {
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State == svc.Stopped {
			return nil
		}
		if state.State == svc.Running {
			if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) && !errors.Is(err, windows.ERROR_SERVICE_CANNOT_ACCEPT_CTRL) {
				// A new StartPending instance does not yet accept controls.
				// Only tolerate that race after observing the transition.
				if !errors.Is(err, windows.ERROR_INVALID_SERVICE_CONTROL) {
					return err
				}
				current, queryErr := s.Query()
				if queryErr != nil {
					return queryErr
				}
				if current.State == svc.Running {
					return err
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%s did not stop for the update: %w", Control, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// UpdatePaths changes only image paths and Engine's matching recovery command.
// Account, privileges, owner ACLs, failure actions and start policy are retained.
// A partial change is recovered by the enclosing signed-update journal.
func UpdatePaths(c Config) error {
	if err := CheckInstallation(c.Directory); err != nil {
		return err
	}
	for _, entry := range []struct{ name, file string }{{Engine, "netswitch-engine.exe"}, {Control, "netswitch.exe"}} {
		if err := updateServicePath(c, entry.name, entry.file); err != nil {
			return err
		}
	}
	return SetOwner(c.Owner)
}

func updateServicePath(c Config, name, file string) error {
	s, err := open(name, windows.SERVICE_CHANGE_CONFIG|windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if status.State != svc.Stopped {
		return fmt.Errorf("%s must be stopped before replacing its path", name)
	}
	config, err := s.Config()
	if err != nil {
		return err
	}
	if !strings.EqualFold(config.ServiceStartName, "LocalSystem") || config.ServiceType != windows.SERVICE_WIN32_OWN_PROCESS {
		return fmt.Errorf("%s has an unexpected service identity", name)
	}
	path, err := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{filepath.Join(c.Directory, file), "service", "--data", c.Data}))
	if err != nil {
		return err
	}
	if err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE, path, nil, nil, nil, nil, nil, nil); err != nil {
		return err
	}
	if name == Engine {
		return s.SetRecoveryCommand(windows.ComposeCommandLine([]string{filepath.Join(c.Directory, "netswitchctl.exe"), "recover", "--engine", "--data", c.Data}))
	}
	return nil
}
