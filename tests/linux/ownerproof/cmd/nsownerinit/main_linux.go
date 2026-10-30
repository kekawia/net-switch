//go:build linux

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "--in-private-netns" {
		if err := runPrivateSuite(); err != nil {
			fmt.Fprintf(os.Stderr, "FLOOR_GUEST_FAILURE stage=private_suite err=%v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	err := runPID1()
	if err != nil {
		fmt.Printf("FLOOR_GUEST_RESULT status=fail err=%q\n", err.Error())
	} else {
		fmt.Printf("FLOOR_GUEST_RESULT status=pass\n")
	}
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Second)
	}
}

func mountPseudoFS() error {
	mounts := []struct {
		dir, fstype string
		mode        os.FileMode
	}{
		{"/proc", "proc", 0555},
		{"/sys", "sysfs", 0555},
		{"/dev", "devtmpfs", 0755},
		{"/sys/kernel/debug", "debugfs", 0700},
		{"/sys/kernel/tracing", "tracefs", 0700},
		{"/sys/fs/cgroup", "cgroup2", 0755},
		{"/tmp", "tmpfs", 01777},
	}
	for _, m := range mounts {
		if err := os.MkdirAll(m.dir, m.mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", m.dir, err)
		}
		if err := unix.Mount(m.fstype, m.dir, m.fstype, 0, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("mount %s on %s: %w", m.fstype, m.dir, err)
		}
	}
	if err := os.MkdirAll("/dev/net", 0755); err != nil {
		return err
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		dev := unix.Mkdev(10, 200)
		if err := unix.Mknod("/dev/net/tun", unix.S_IFCHR|0666, int(dev)); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("mknod /dev/net/tun: %w", err)
		}
	}
	return nil
}

func verifyFloorKernel() error {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return err
	}
	rel := unix.ByteSliceToString(uts.Release[:])
	machine := unix.ByteSliceToString(uts.Machine[:])
	version := unix.ByteSliceToString(uts.Version[:])
	fmt.Printf("FLOOR_GUEST_BOOT release=%s machine=%s goarch=%s cpus=%d version=%q\n", rel, machine, runtime.GOARCH, runtime.NumCPU(), version)
	if rel != "5.8.0" {
		return fmt.Errorf("unexpected floor kernel release %q (want 5.8.0)", rel)
	}
	if runtime.NumCPU() < 2 {
		return fmt.Errorf("floor guest requires at least 2 CPUs, got %d", runtime.NumCPU())
	}
	btfInfo, err := os.Stat("/sys/kernel/btf/vmlinux")
	if err != nil || btfInfo.Size() == 0 {
		return fmt.Errorf("missing /sys/kernel/btf/vmlinux: %v", err)
	}
	fmt.Printf("FLOOR_GUEST_BTF path=/sys/kernel/btf/vmlinux bytes=%d\n", btfInfo.Size())

	gzBytes, err := os.ReadFile("/proc/config.gz")
	if err != nil {
		return fmt.Errorf("read /proc/config.gz: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gzBytes))
	if err != nil {
		return fmt.Errorf("gunzip /proc/config.gz: %w", err)
	}
	cfgBytes, err := io.ReadAll(zr)
	_ = zr.Close()
	if err != nil {
		return fmt.Errorf("decompress /proc/config.gz: %w", err)
	}
	if err := os.MkdirAll("/boot", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("/boot/config-"+rel, cfgBytes, 0644); err != nil {
		return fmt.Errorf("write /boot/config-%s: %w", rel, err)
	}
	cfgSum := sha256.Sum256(cfgBytes)
	fmt.Printf("FLOOR_GUEST_RUNNING_CONFIG release=%s bytes=%d sha256=%s\n", rel, len(cfgBytes), hex.EncodeToString(cfgSum[:]))
	for _, line := range strings.Split(string(cfgBytes), "\n") {
		if strings.HasPrefix(line, "CONFIG_BPF") || strings.HasPrefix(line, "CONFIG_DEBUG_INFO") || strings.HasPrefix(line, "CONFIG_PREEMPT") || strings.HasPrefix(line, "CONFIG_NET_SCH_NETEM") || strings.HasPrefix(line, "CONFIG_HZ") {
			fmt.Printf("FLOOR_GUEST_KCONFIG %s\n", line)
		}
	}
	return nil
}

func runPID1() error {
	if os.Getpid() != 1 {
		return fmt.Errorf("nsownerinit must run as PID 1, got pid %d", os.Getpid())
	}
	if err := mountPseudoFS(); err != nil {
		return err
	}
	if err := verifyFloorKernel(); err != nil {
		return err
	}
	// Run the test suite in a child process with CLONE_NEWNET while PID 1 stays
	// in the initial network namespace, satisfying /proc/self/ns/net != /proc/1/ns/net.
	cmd := exec.Command("/init", "--in-private-netns")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWNET,
	}
	return cmd.Run()
}

func runPrivateSuite() error {
	target := "x86"
	if runtime.GOARCH == "arm64" {
		target = "arm64"
	}
	proofObj := fmt.Sprintf("/ownerbpf/proof_%s_bpfel.o", target)
	bridgeObj := fmt.Sprintf("/ownerbpf/bridge_%s_bpfel.o", target)
	faultObj := fmt.Sprintf("/ownerbpf/fault_%s_bpfel.o", target)
	for _, path := range []string{"/bin/ownerbpf-proof.test", proofObj, bridgeObj, faultObj} {
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("missing initramfs payload %s: %w", path, err)
		}
		sum := sha256.Sum256(b)
		fmt.Printf("FLOOR_GUEST_INPUT path=%s bytes=%d sha256=%s\n", path, len(b), hex.EncodeToString(sum[:]))
	}

	baseEnv := append(os.Environ(),
		"GOMAXPROCS=2",
		"NS_OWNERBPF_PROOF=1",
		"NS_OWNERBPF_FLOOR58=1",
		"NS_OWNERBPF_KERNEL=5.8.0",
		"NS_OWNERBPF_OBJECT="+proofObj,
		"NS_BRIDGE_OBJECT="+bridgeObj,
		"NS_BRIDGE_FAULT_OBJECT="+faultObj,
	)

	suites := []struct {
		name    string
		pattern string
		timeout string
	}{
		{"kernel-proof", "^TestKernelProof$", "5m"},
		{"bridge-proof", "^TestBridge", "15m"},
	}
	for _, s := range suites {
		fmt.Printf("FLOOR_GUEST_SUITE_START suite=%s pattern=%s\n", s.name, s.pattern)
		cmd := exec.Command("/bin/ownerbpf-proof.test", "-test.v", "-test.count=1", "-test.timeout="+s.timeout, "-test.run="+s.pattern)
		cmd.Env = baseEnv
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		start := time.Now()
		err := cmd.Run()
		elapsed := time.Since(start)
		if err != nil {
			fmt.Printf("FLOOR_GUEST_SUITE_END suite=%s status=fail elapsed_ms=%d err=%v\n", s.name, elapsed.Milliseconds(), err)
			return fmt.Errorf("suite %s failed: %w", s.name, err)
		}
		fmt.Printf("FLOOR_GUEST_SUITE_END suite=%s status=pass elapsed_ms=%d\n", s.name, elapsed.Milliseconds())
	}
	return nil
}
