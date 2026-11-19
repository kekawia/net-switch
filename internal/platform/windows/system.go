package winplatform

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/kekawia/net-switch/internal/platform/windows/observer"
	"github.com/kekawia/net-switch/internal/platform/worker"
)

// Run dispatches Control's one-shot queries and probes, and delegates blocking
// observer modes to the leaf observer package.
func Run(args []string) int {
	if len(args) > 0 && args[0] == "query" {
		return query(args[1:], false)
	}
	if len(args) > 0 && args[0] == "query-supervised" {
		return query(args[1:], true)
	}
	if len(args) > 0 && args[0] == "probe" {
		return runProbe(args[1:])
	}
	return observer.Run(args)
}

type System struct {
	Workers                               worker.Supervisor
	StreamExecutable                      string
	EnginePath, Root, UserDir, MachineDir string
}

func (s *System) Call(ctx context.Context, operation string, args map[string]any) (any, error) {
	if operation == "elevated" {
		return ControlElevated()
	}
	if operation == "autostart-set" || operation == "autostart-upgrade" {
		copy := map[string]any{}
		for k, v := range args {
			copy[k] = v
		}
		copy["executable"] = s.Workers.Executable
		copy["root"] = s.Root
		copy["userDir"] = s.UserDir
		copy["machineDir"] = s.MachineDir
		args = copy
	}
	return s.Workers.Once(ctx, operation, args)
}
func (s *System) Stream(ctx context.Context, mode string, emit func([]byte), report func(error)) {
	args := []string{}
	if mode == "outside" {
		args = append(args, "--engine", s.EnginePath)
	}
	supervisor := s.Workers
	switch mode {
	case "meters", "outside", "network":
		if s.StreamExecutable != "" {
			supervisor.Executable = s.StreamExecutable
		}
	}
	supervisor.Stream(ctx, mode, args, emit, report)
}
func query(args []string, supervised bool) int {
	if len(args) != 1 && len(args) != 2 {
		fmt.Fprintln(os.Stderr, "worker query needs an operation and encoded arguments")
		return 2
	}
	var b []byte
	var err error
	if len(args) == 2 {
		b, err = base64.RawURLEncoding.DecodeString(args[1])
	} else {
		b, err = io.ReadAll(io.LimitReader(os.Stdin, 4*1024*1024+1))
		if len(b) > 4*1024*1024 {
			err = fmt.Errorf("worker request exceeds 4 MiB")
		}
	}
	var input map[string]any
	if err == nil {
		err = json.Unmarshal(b, &input)
	}
	var value any
	if err == nil {
		if supervised {
			var executable string
			executable, err = os.Executable()
			if err == nil {
				if args[0] == "elevated" {
					value, err = ControlElevated()
				} else {
					value, err = (worker.Supervisor{Executable: executable}).Once(context.Background(), args[0], input)
				}
			}
		} else {
			value, err = Execute(args[0], input)
		}
	}
	result := map[string]any{"value": value}
	if err != nil {
		result["error"] = err.Error()
	}
	if err := observer.WriteLine(result); err != nil {
		return 1
	}
	return 0
}
