package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/service"
)

func ServiceCommand(name string, args []string) error {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	data := flags.String("data", DefaultData(), "protected machine store")
	if err := flags.Parse(args); err != nil {
		return err
	}
	return service.Run(name, func(ctx context.Context, ready func()) error {
		c, err := LoadConfig(*data)
		if err != nil {
			service.ReportError(name, err)
			return err
		}
		log := Log(c.Data, name)
		run := ControlService
		if name == service.Engine {
			run = nativeEngineService
		}
		err = run(ctx, ready, c, log)
		if err != nil {
			log("service failed: " + err.Error())
			service.ReportError(name, err)
		}
		return err
	})
}
func Ctl(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: netswitchctl status|enroll|start|stop|journal|install|cleanup|recover|uninstall|migration-check|migrate-profiles|migrate|restore-windows|cleanup-machine-data|whoami|version")
	}
	command := args[0]
	if command == "version" {
		fmt.Println("netswitchctl", buildinfo.String())
		return nil
	}
	flags := flag.NewFlagSet("netswitchctl "+command, flag.ContinueOnError)
	data := flags.String("data", DefaultData(), "protected machine store")
	machineData := flags.String("machine-data", "", "protected machine store alias")
	dir := flags.String("directory", "", "directory containing the service executables")
	appDir := flags.String("app-dir", "", "root versioned installation directory")
	stageDir := flags.String("stage-dir", "", "temporary stage directory to copy and verify")
	versionFlag := flags.String("version", "", "target semantic version for versioned layout")
	profileFlag := flags.String("profile", "", "selected Windows user profile SID for migration")
	outPath := flags.String("out", "", "optional JSON output file path")
	wizardOutPath := flags.String("wizard-out", "", "optional line-formatted wizard output file path")
	sidOutPath := flags.String("sid-out", "", "optional SID text output file path")
	errorOutPath := flags.String("error-out", "", "optional installer error text output file path")
	adapter := flags.String("adapter", "", "retired stand-in flag (rejected by install)")
	mode := flags.String("mode", "tun", "tun or proxy")
	ownerBackend := flags.String("owner-backend", "", "Linux attribution backend (auto, ebpf, or proc-fallback)")
	ownerName := flags.String("owner", "", "interactive owner to enroll; omit to leave pending")
	engine := flags.Bool("engine", false, "engine recovery")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *machineData != "" {
		*data = *machineData
	}
	switch command {
	case "install", "status", "start", "stop", "whoami", "migrate-profiles", "migrate", "restore-windows", "cleanup-machine-data", "harden-root", "uninstall":
	default:
		resolved, err := ResolveStore(*data)
		if err != nil {
			return err
		}
		*data = resolved
	}
	ctxTimeout := 45 * time.Second
	if command == "migrate" || (command == "install" && *appDir != "") {
		ctxTimeout = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), ctxTimeout)
	defer cancel()
	printJSON := func(value any, err error) error {
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(value)
	}
	switch command {
	case "whoami":
		owner, err := WhoamiCommand(*outPath, *sidOutPath)
		return printJSON(owner, err)
	case "migrate-profiles":
		res, err := MigrateProfiles(*appDir, *ownerName, *outPath, *wizardOutPath)
		return printJSON(res, err)
	case "migrate":
		err := Migrate(ctx, MigrateOptions{
			AppDir:   *appDir,
			StageDir: *stageDir,
			Version:  *versionFlag,
			Owner:    *ownerName,
			Profile:  *profileFlag,
			DataDir:  *data,
			OutPath:  *outPath,
		})
		WriteInstallerError(*errorOutPath, err)
		return err
	case "harden-root":
		return HardenInstallRootCommand(*appDir)
	case "restore-windows":
		return RestoreWindows(*data)
	case "cleanup-machine-data":
		return CleanupMachineDataCommand(*data)
	case "status", "start", "stop":
		if command != "status" {
			if err := service.Activate(ctx); err != nil {
				return err
			}
		}
		var rpc *RPC
		var err error
		if command == "status" {
			rpc, err = ConnectStatus(ctx)
		} else {
			rpc, err = ConnectDesktop(ctx, false)
		}
		if err != nil {
			return err
		}
		defer rpc.Close()
		request := map[string]any{"method": "status"}
		if command != "status" {
			request = map[string]any{"method": "routing", "on": command == "start"}
		}
		var result any
		err = rpc.Call(ctx, request, &result)
		return printJSON(result, err)
	case "journal", "migration-check":
		value, err := Inspect(*data)
		return printJSON(value, err)
	case "enroll", "enrol":
		if !Administrator() {
			return errors.New("enrollment requires an administrator")
		}
		name := *ownerName
		if flags.NArg() == 1 {
			name = flags.Arg(0)
		}
		// A changed owner replaces Control and revokes every browser token,
		// while preserving the engine and the durable routing intent.
		owner, err := Enroll(ctx, *data, name)
		if err != nil {
			return err
		}
		if err := settleOwner(ctx, owner.User, installedOwnerServices()); err != nil {
			return err
		}
		return printJSON(owner, nil)
	case "install":
		if !Administrator() {
			return errors.New("install requires an administrator")
		}
		if *appDir != "" || *versionFlag != "" {
			if *appDir == "" || *versionFlag == "" {
				return errors.New("--app-dir and --version are required together")
			}
			if *adapter != "" {
				return errors.New("native service qualification requires tun mode and no adapter")
			}
			err := InstallVersioned(ctx, InstallVersionedOptions{
				AppDir:       *appDir,
				StageDir:     *stageDir,
				Version:      *versionFlag,
				Owner:        *ownerName,
				DataDir:      *data,
				Mode:         *mode,
				OwnerBackend: *ownerBackend,
			})
			WriteInstallerError(*errorOutPath, err)
			return err
		}
		if *dir == "" {
			return errors.New("--directory is required")
		}
		var err error
		*dir, err = filepath.Abs(*dir)
		if err != nil {
			return err
		}
		*data, err = filepath.Abs(*data)
		if err != nil {
			return err
		}
		if *mode != "tun" && *mode != "proxy" {
			return errors.New("mode must be tun or proxy")
		}
		if *adapter != "" || *mode != "tun" {
			return errors.New("native service qualification requires tun mode and no adapter")
		}
		if *ownerBackend != "" && *ownerBackend != "auto" && *ownerBackend != "proc-fallback" && *ownerBackend != "ebpf" {
			return errors.New("owner-backend must be auto, ebpf, or proc-fallback")
		}
		if err := service.CheckInstallation(*dir); err != nil {
			return err
		}
		*data, err = PrepareStore(*data)
		if err != nil {
			return err
		}
		if err := refuseStandInStore(*data); err != nil {
			return err
		}
		c := Config{Directory: *dir, Data: *data, Mode: *mode, OwnerBackend: *ownerBackend}
		if err := Save(filepath.Join(*data, "service-config.json"), c); err != nil {
			return err
		}
		var owner Owner
		if *ownerName != "" {
			owner, err = Enroll(ctx, *data, *ownerName)
			if err != nil {
				return err
			}
		}
		return service.Install(service.Config{Directory: *dir, Data: *data, Owner: owner.User, Native: true})
	case "cleanup", "recover":
		if !Administrator() {
			return errors.New("cleanup requires an administrator")
		}
		if !*engine {
			return errors.New("specify --engine")
		}
		if err := CheckDirectory(*data); err != nil {
			return err
		}
		short, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		return Cleanup(short, *data)
	case "uninstall":
		if !Administrator() {
			return errors.New("uninstall requires an administrator")
		}
		resolved, rErr := ResolveStore(*data)
		appRoot := *appDir
		if rErr == nil && CheckDirectory(resolved) == nil {
			if owner, oErr := LoadOwner(resolved); oErr == nil && owner.User != "" {
				_ = setOwnerRunKey(owner.User, "", false)
			}
			var rawCfg Config
			if Read(filepath.Join(resolved, "service-config.json"), &rawCfg) == nil && rawCfg.Directory != "" {
				if appRoot == "" && isVersionedAppSubdir(filepath.Base(rawCfg.Directory)) {
					appRoot = filepath.Dir(rawCfg.Directory)
				}
			}
		}
		if appRoot != "" {
			_ = StopInstalledDesktopProcesses(appRoot)
		}
		if err := service.Uninstall(ctx); err != nil {
			return err
		}
		if rErr != nil {
			return nil
		}
		if _, statErr := os.Lstat(resolved); errors.Is(statErr, os.ErrNotExist) {
			return nil
		}
		return Cleanup(ctx, resolved)
	default:
		return fmt.Errorf("unknown command %q (%s)", command, runtime.GOOS)
	}
}
