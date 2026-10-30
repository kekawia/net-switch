package ownerproof

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

//go:embed guest.lock.json
var rawGuestLock []byte

//go:embed kernel-5.8-amd64.config
var rawKernelConfigAMD64 []byte

//go:embed kernel-5.8-arm64.config
var rawKernelConfigARM64 []byte

type GuestLock struct {
	SchemaVersion int    `json:"schemaVersion"`
	Profile       string `json:"profile"`
	Kernel        struct {
		Tag                  string                       `json:"tag"`
		Release              string                       `json:"release"`
		SourceCommit         string                       `json:"sourceCommit"`
		TarballURL           string                       `json:"tarballUrl"`
		TarballSHA256        string                       `json:"tarballSha256"`
		RawRecursionGuard    bool                         `json:"rawRecursionGuard"`
		RecursionMissesField bool                         `json:"recursionMissesField"`
		Configs              map[string]KernelArchProfile `json:"configs"`
	} `json:"kernel"`
	CompilerImage struct {
		Repository            string            `json:"repository"`
		Tag                   string            `json:"tag"`
		IndexDigest           string            `json:"indexDigest"`
		Platforms             map[string]string `json:"platforms"`
		SPDXAttestationDigest string            `json:"spdxAttestationDigest"`
		BasePackages          map[string]string `json:"basePackages"`
	} `json:"compilerImage"`
	DebianPackages struct {
		Mirror          string          `json:"mirror"`
		Suite           string          `json:"suite"`
		ReleaseVersion  string          `json:"releaseVersion"`
		AMD64           []PinnedPackage `json:"amd64"`
		ARM64           []PinnedPackage `json:"arm64"`
		QEMURunnerAMD64 []PinnedPackage `json:"qemuRunnerAmd64"`
	} `json:"debianPackages"`
	Initramfs struct {
		GoVersion          string                       `json:"goVersion"`
		PID1Package        string                       `json:"pid1Package"`
		ProofTestPackage   string                       `json:"proofTestPackage"`
		ProofTestTag       string                       `json:"proofTestTag"`
		BPFGeneratorScript string                       `json:"bpfGeneratorScript"`
		BPFObjects         map[string]map[string]string `json:"bpfObjects"`
	} `json:"initramfs"`
	Outputs struct {
		ReproducibilityStage string `json:"reproducibilityStage"`
		AMD64                struct {
			KernelImageSHA256 *string `json:"kernelImageSha256"`
			InitramfsSHA256   *string `json:"initramfsSha256"`
		} `json:"amd64"`
		ARM64 struct {
			KernelImageSHA256 *string `json:"kernelImageSha256"`
			InitramfsSHA256   *string `json:"initramfsSha256"`
		} `json:"arm64"`
	} `json:"outputs"`
}

type KernelArchProfile struct {
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	BaseDefconfig     string `json:"baseDefconfig"`
	ImageTarget       string `json:"imageTarget"`
	ImageRelativePath string `json:"imageRelativePath"`
	QEMUBinary        string `json:"qemuBinary"`
	Accelerator       string `json:"accelerator"`
	Console           string `json:"console"`
	CPUs              int    `json:"cpus"`
	MemoryMiB         int    `json:"memoryMiB"`
}

type PinnedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
}

func LoadGuestLock() (*GuestLock, error) {
	var lock GuestLock
	if err := json.Unmarshal(rawGuestLock, &lock); err != nil {
		return nil, err
	}
	if err := ValidateGuestLock(&lock); err != nil {
		return nil, err
	}
	return &lock, nil
}

func EmbeddedKernelConfig(arch string) ([]byte, error) {
	switch arch {
	case "amd64":
		return append([]byte(nil), rawKernelConfigAMD64...), nil
	case "arm64":
		return append([]byte(nil), rawKernelConfigARM64...), nil
	default:
		return nil, fmt.Errorf("unsupported floor guest architecture %q", arch)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func ValidateGuestLock(lock *GuestLock) error {
	if lock == nil {
		return errors.New("nil guest lock")
	}
	if lock.SchemaVersion != 1 || lock.Profile != "linux-5.8-floor-guest" {
		return fmt.Errorf("unexpected guest lock schema/profile: %d %q", lock.SchemaVersion, lock.Profile)
	}
	if lock.Kernel.Tag != "v5.8" || lock.Kernel.Release != "5.8.0" ||
		lock.Kernel.SourceCommit != "bcf876870b95592b52519ed4aafcf9d95999bc9c" ||
		lock.Kernel.TarballSHA256 != "e7f75186aa0642114af8f19d99559937300ca27acaf7451b36d4f9b0f85cf1f5" {
		return fmt.Errorf("unexpected v5.8 kernel pin: %+v", lock.Kernel)
	}
	if lock.Kernel.RawRecursionGuard || lock.Kernel.RecursionMissesField {
		return errors.New("upstream v5.8 floor profile must record rawRecursionGuard=false and recursionMissesField=false")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		cfg, ok := lock.Kernel.Configs[arch]
		if !ok {
			return fmt.Errorf("missing kernel config profile for %s", arch)
		}
		raw, err := EmbeddedKernelConfig(arch)
		if err != nil {
			return err
		}
		if got := sha256Hex(raw); got != cfg.SHA256 {
			return fmt.Errorf("%s kernel config sha256 mismatch: embedded=%s lock=%s", arch, got, cfg.SHA256)
		}
		if err := ValidateKernelConfigText(arch, string(raw)); err != nil {
			return err
		}
		if cfg.CPUs != 2 || cfg.MemoryMiB != 2048 {
			return fmt.Errorf("%s floor guest must use 2 CPUs and 2048 MiB, got cpus=%d mem=%d", arch, cfg.CPUs, cfg.MemoryMiB)
		}
	}
	if lock.Kernel.Configs["amd64"].Accelerator != "kvm" || lock.Kernel.Configs["arm64"].Accelerator != "tcg" {
		return errors.New("floor guest accelerator contract mismatch: amd64 requires kvm and arm64 requires tcg")
	}
	if lock.CompilerImage.IndexDigest != "sha256:ccb050a415a94a3a78acbe35084ec8f06ae46fa158e3650c96f9b4fb514de6d3" ||
		lock.CompilerImage.Platforms["amd64"] != "sha256:0ac99c7dcee4d051ea036dd4dc6db33cef4c5d2088c0bed4001d81e3d6cf53bd" ||
		lock.CompilerImage.Platforms["arm64"] != "sha256:a90d803a53c4af08fd5c51a289eec7d9f45f5a5dc09af60c25c59a1b25f20b84" {
		return fmt.Errorf("compiler container digest mismatch: %+v", lock.CompilerImage)
	}
	for _, list := range [][]PinnedPackage{lock.DebianPackages.AMD64, lock.DebianPackages.ARM64, lock.DebianPackages.QEMURunnerAMD64} {
		if len(list) == 0 {
			return errors.New("empty pinned package list")
		}
		for _, pkg := range list {
			if pkg.Name == "" || pkg.Version == "" || pkg.Path == "" || len(pkg.SHA256) != 64 {
				return fmt.Errorf("invalid pinned package entry: %+v", pkg)
			}
		}
	}
	return nil
}

func ValidateKernelConfigText(arch, text string) error {
	required := []string{
		"CONFIG_BPF=y",
		"CONFIG_BPF_SYSCALL=y",
		"CONFIG_BPF_JIT=y",
		"CONFIG_BPF_JIT_ALWAYS_ON=y",
		"CONFIG_DEBUG_INFO=y",
		"CONFIG_DEBUG_INFO_DWARF4=y",
		"CONFIG_DEBUG_INFO_BTF=y",
		"CONFIG_CGROUPS=y",
		"CONFIG_CGROUP_BPF=y",
		"CONFIG_NET_NS=y",
		"CONFIG_KPROBES=y",
		"CONFIG_BPF_EVENTS=y",
		"CONFIG_PERF_EVENTS=y",
		"CONFIG_TRACEPOINTS=y",
		"CONFIG_TUN=y",
		"CONFIG_PACKET=y",
		"CONFIG_NET_SCH_NETEM=y",
		"CONFIG_BLK_DEV_INITRD=y",
		"CONFIG_DEVTMPFS=y",
		"CONFIG_PROC_FS=y",
		"CONFIG_SYSFS=y",
		"CONFIG_DEBUG_FS=y",
		"CONFIG_IKCONFIG=y",
		"CONFIG_IKCONFIG_PROC=y",
		"CONFIG_SMP=y",
		"CONFIG_PREEMPT=y",
		"CONFIG_HIGH_RES_TIMERS=y",
		"CONFIG_HZ_1000=y",
	}
	lines := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		lines[strings.TrimSpace(line)] = true
	}
	for _, req := range required {
		if !lines[req] {
			return fmt.Errorf("%s kernel config missing required setting %s", arch, req)
		}
	}
	return nil
}
