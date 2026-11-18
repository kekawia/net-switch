package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/kekawia/net-switch/internal/control"
	"github.com/kekawia/net-switch/internal/service"
)

const packageDir = "/usr/lib/netswitch"
const packageSocket = "netswitch.socket"
const packageControl = "netswitch.service"
const packageEngine = "netswitch-engine.service"

// Reject manual install/uninstall before either can rewrite package config
// or remove administrator overrides from /etc/systemd/system.
func checkManualInstall() error {
	_, err := os.Lstat(filepath.Join("/usr/lib/systemd/system", packageEngine))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.New("manage this Net Switch installation with your Linux package manager")
}

type packageState struct {
	Schema                   int
	Operation                string
	Socket, Control, Enabled bool
}

func packageMarker() string { return filepath.Join(DefaultData(), service.PackageMaintenanceFile) }

// Moving the marker to this name opens systemd activation while preserving
// the original activity record until all requested starts have succeeded.
func activationRecord() string { return packageMarker() + ".activating" }

func readPackageState(file string) (packageState, error) {
	var s packageState
	if err := Read(file, &s); err != nil {
		return s, err
	}
	if s.Schema != 1 || (s.Operation != "upgrade" && s.Operation != "remove" && s.Operation != "install") {
		return s, errors.New("invalid package maintenance record")
	}
	return s, nil
}

func stopInstalledControl(ctx context.Context, data string, c *control.Core) error {
	if data == DefaultData() {
		s, err := readPackageState(packageMarker())
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if s.Operation == "upgrade" {
			return c.ShutdownForPackageUpgrade(ctx)
		}
	}
	return c.ShutdownForService(ctx)
}

func packageCommand(args []string) error {
	if len(args) == 2 && args[0] == "unit" {
		units, err := service.PackageUnits(service.Config{Directory: packageDir, Data: DefaultData()})
		if err != nil {
			return err
		}
		body, ok := units[args[1]]
		if !ok {
			return errors.New("unknown package unit")
		}
		_, err = fmt.Print(body)
		return err
	}
	if len(args) != 2 || (args[1] != "deb" && args[1] != "rpm" && args[1] != "arch") {
		return errors.New("usage: netswitchctl package unit NAME | configure|upgrade|remove|abort FORMAT")
	}
	switch args[0] {
	case "configure", "abort", "upgrade", "remove":
	default:
		return fmt.Errorf("unknown package action %q", args[0])
	}
	data, err := PrepareStore(DefaultData())
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	release, err := (Lock{Data: data, Name: "package"}).Acquire(ctx)
	if err != nil {
		return err
	}
	defer release()
	p := packageManager{ctx: ctx, format: args[1]}
	if args[0] == "configure" || args[0] == "abort" {
		return p.finish(args[0] == "abort")
	}
	return p.prepare(args[0])
}

type packageManager struct {
	ctx    context.Context
	format string
}

func (p packageManager) systemctl(args ...string) (string, error) {
	cmd := exec.CommandContext(p.ctx, "/usr/bin/systemctl", args...)
	cmd.Env = service.ChildEnvironment()
	b, err := cmd.CombinedOutput()
	result := strings.TrimSpace(string(b))
	if err != nil {
		return result, fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), err, result)
	}
	return result, nil
}

func (p packageManager) active(unit string) (bool, error) {
	state, err := p.systemctl("show", "--property=ActiveState", "--value", unit)
	if err != nil {
		return false, err
	}
	switch state {
	case "active", "activating", "reloading":
		return true, nil
	case "inactive", "failed", "deactivating":
		return false, nil
	}
	return false, fmt.Errorf("unknown state %q for %s", state, unit)
}

func (p packageManager) permitted(unit, action string) (bool, error) {
	const policy = "/usr/sbin/policy-rc.d"
	if p.format != "deb" {
		return true, nil
	}
	fi, err := os.Stat(policy)
	if os.IsNotExist(err) || (err == nil && fi.Mode().Perm()&0111 == 0) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	err = exec.CommandContext(p.ctx, policy, unit, action).Run()
	var result *exec.ExitError
	if errors.As(err, &result) {
		switch result.ExitCode() {
		case 101:
			return false, nil
		case 104:
			return true, nil
		}
	}
	return err == nil, err
}

func systemdRunning() bool {
	fi, err := os.Stat("/run/systemd/system")
	return err == nil && fi.IsDir()
}

func (p packageManager) prepare(op string) error {
	if systemdRunning() {
		if err := p.checkStopPolicy(); err != nil {
			return err
		}
	}
	marker := packageMarker()
	s, err := readPackageState(marker)
	if os.IsNotExist(err) {
		if _, err := os.Lstat(activationRecord()); !os.IsNotExist(err) {
			return errors.New("finish the previous package configuration first")
		}
		s = packageState{Schema: 1, Operation: op}
		if systemdRunning() {
			if s.Socket, err = p.active(packageSocket); err != nil {
				return err
			}
			if s.Control, err = p.active(packageControl); err != nil {
				return err
			}
		}
		unitState, _ := p.systemctl("is-enabled", packageSocket)
		s.Enabled = unitState == "enabled"
		if err := saveNative(marker, s); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if s.Operation != op {
		return fmt.Errorf("unfinished package %s", s.Operation)
	}
	if systemdRunning() {
		if _, err := p.systemctl("stop", packageSocket, packageControl); err != nil {
			return err
		}
		if _, err := p.systemctl("stop", packageEngine); err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(DefaultData(), "engine-journal.json")); err == nil {
			if err := Cleanup(p.ctx, DefaultData()); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if op == "remove" && s.Enabled {
		if _, err := p.systemctl("disable", packageSocket); err != nil {
			return err
		}
	}
	return nil
}

func (p packageManager) checkStopPolicy() error {
	for _, unit := range []string{packageSocket, packageControl, packageEngine} {
		active, err := p.active(unit)
		if err != nil {
			return err
		}
		if !active {
			continue
		}
		ok, err := p.permitted(unit, "stop")
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("service policy prevents stopping %s", unit)
		}
	}
	return nil
}

func packageConfig() error {
	dir := DefaultData()
	if err := service.CheckInstallation(packageDir); err != nil {
		return err
	}
	if err := refuseStandInStore(dir); err != nil {
		return err
	}
	c, err := LoadConfig(dir)
	if os.IsNotExist(err) {
		// Only a missing primary config is a new install. A missing executable
		// under a retained manual installation must not replace its config.
		path := filepath.Join(dir, "service-config.json")
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			return err
		}
		if _, statErr := os.Lstat(path + ".bak"); !os.IsNotExist(statErr) {
			return errors.New("restore the retained service configuration before installing")
		}
		return Save(path, Config{Directory: packageDir, Data: dir, Mode: "tun"})
	}
	if err != nil {
		return err
	}
	if c.Directory != packageDir {
		return errors.New("existing service configuration belongs to a different installation")
	}
	return nil
}

func (p packageManager) finish(abort bool) error {
	marker, next := packageMarker(), activationRecord()
	s, err := readPackageState(marker)
	if os.IsNotExist(err) {
		s, err = readPackageState(next)
		if os.IsNotExist(err) {
			if abort {
				return nil
			}
			if _, installed := os.Stat(filepath.Join(DefaultData(), "package-installed")); installed == nil {
				return packageConfig()
			} else if !os.IsNotExist(installed) {
				return installed
			}
			s = packageState{Schema: 1, Operation: "install", Socket: true}
			if err = saveNative(marker, s); err != nil {
				return err
			}
		}
	}
	if err != nil {
		return err
	}
	if s.Operation == "remove" && !abort {
		// A fresh install following removal retains the user's data but
		// follows first-install activation policy.
		s = packageState{Schema: 1, Operation: "install", Socket: true}
		if err := saveNative(marker, s); err != nil {
			return err
		}
	}
	if err := packageConfig(); err != nil {
		return err
	}
	live := systemdRunning()
	if live {
		if _, err := p.systemctl("daemon-reload"); err != nil {
			return err
		}
	}
	if s.Operation == "install" || (abort && s.Operation == "remove" && s.Enabled) {
		state, _ := p.systemctl("is-enabled", packageSocket)
		if state == "masked" || state == "masked-runtime" {
			s.Socket = false
		} else if _, err := p.systemctl("enable", packageSocket); err != nil {
			return err
		}
	}
	if err := os.Rename(marker, next); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := SyncDirectory(DefaultData()); err != nil {
		return err
	}
	if live {
		for _, u := range []struct {
			name  string
			start bool
		}{{packageSocket, s.Socket}, {packageControl, s.Control}} {
			if !u.start {
				continue
			}
			ok, err := p.permitted(u.name, "start")
			if err != nil {
				return err
			}
			if ok {
				if _, err := p.systemctl("start", u.name); err != nil {
					return err
				}
			}
		}
	}
	if err := saveNative(filepath.Join(DefaultData(), "package-installed"), true); err != nil {
		return err
	}
	if err := os.Remove(next); err != nil {
		return err
	}
	return SyncDirectory(DefaultData())
}
