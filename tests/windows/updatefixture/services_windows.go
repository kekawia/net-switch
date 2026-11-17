package main

import (
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// Query only configuration. The engine deliberately denies administrators
// start/stop rights, so a management provider requesting broader access can
// omit PathName even while the service exists and runs correctly.
func printServicePaths() error {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)
	paths := map[string]string{}
	for _, name := range []string{"NetSwitch", "NetSwitchEngine"} {
		encoded, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return err
		}
		handle, err := windows.OpenService(manager, encoded, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			return fmt.Errorf("query %s: %w", name, err)
		}
		s := &mgr.Service{Name: name, Handle: handle}
		config, queryErr := s.Config()
		closeErr := s.Close()
		if queryErr != nil {
			return fmt.Errorf("read %s configuration: %w", name, queryErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if config.BinaryPathName == "" {
			return fmt.Errorf("%s has an empty SCM binary path", name)
		}
		paths[name] = config.BinaryPathName
	}
	return json.NewEncoder(os.Stdout).Encode(paths)
}
