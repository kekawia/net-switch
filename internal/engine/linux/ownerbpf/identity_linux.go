//go:build linux

package ownerbpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	pfKthread       = 0x00200000
	maxProcReadSize = 64 << 10
)

func readBoundedFD(fd int, maxBytes int) ([]byte, error) {
	buf := make([]byte, maxBytes)
	total := 0
	for total < len(buf) {
		n, err := unix.Read(fd, buf[total:])
		if n > 0 {
			total += n
		}
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return nil, err
		}
		if n == 0 {
			break
		}
	}
	return buf[:total], nil
}

func parseProcStat(raw string) (startTicks uint64, kernelThread bool, err error) {
	closeParen := strings.LastIndexByte(raw, ')')
	if closeParen < 0 || closeParen+2 >= len(raw) {
		return 0, false, errors.New("malformed /proc/stat line")
	}
	fields := strings.Fields(raw[closeParen+1:])
	// fields[0] is field 3 (state), fields[6] is field 9 (flags), fields[19] is field 22 (starttime).
	if len(fields) < 20 {
		return 0, false, errors.New("truncated /proc/stat fields")
	}
	flags, err := strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse /proc/stat flags: %w", err)
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, false, fmt.Errorf("parse /proc/stat starttime: %w", err)
	}
	return ticks, (flags & pfKthread) != 0, nil
}

func parseProcStatusCreds(raw string) (uid, gid uint32, err error) {
	var gotUID, gotGID bool
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(f) < 1 {
				return 0, 0, errors.New("malformed Uid line in /proc/status")
			}
			v, parseErr := strconv.ParseUint(f[0], 10, 32)
			if parseErr != nil {
				return 0, 0, parseErr
			}
			uid = uint32(v)
			gotUID = true
		} else if strings.HasPrefix(line, "Gid:") {
			f := strings.Fields(strings.TrimPrefix(line, "Gid:"))
			if len(f) < 1 {
				return 0, 0, errors.New("malformed Gid line in /proc/status")
			}
			v, parseErr := strconv.ParseUint(f[0], 10, 32)
			if parseErr != nil {
				return 0, 0, parseErr
			}
			gid = uint32(v)
			gotGID = true
		}
	}
	if !gotUID || !gotGID {
		return 0, 0, errors.New("missing Uid/Gid in /proc/status")
	}
	return uid, gid, nil
}

// HasAsyncSubmitter reports whether the target process currently holds an
// open io_uring instance or runs an io_uring sqpoll/io-wq worker thread.
func HasAsyncSubmitter(tgid uint32) bool {
	pidStr := strconv.FormatUint(uint64(tgid), 10)
	fdEntries, err := os.ReadDir(filepath.Join("/proc", pidStr, "fd"))
	if err == nil {
		for _, entry := range fdEntries {
			target, linkErr := os.Readlink(filepath.Join("/proc", pidStr, "fd", entry.Name()))
			if linkErr == nil && strings.Contains(target, "[io_uring]") {
				return true
			}
		}
	}
	taskEntries, err := os.ReadDir(filepath.Join("/proc", pidStr, "task"))
	if err == nil {
		for _, entry := range taskEntries {
			commBytes, commErr := os.ReadFile(filepath.Join("/proc", pidStr, "task", entry.Name(), "comm"))
			if commErr != nil {
				continue
			}
			comm := strings.TrimSpace(string(commBytes))
			if strings.HasPrefix(comm, "iou-sqp") || strings.HasPrefix(comm, "iou-wrk") {
				return true
			}
		}
	}
	return false
}

// SampleExecutionContext reads one execution-context point sample from /proc/<tgid>.
func SampleExecutionContext(tgid uint32, startBoottime, execID uint64) (ExecutionContext, []MountEntry, error) {
	pidStr := strconv.FormatUint(uint64(tgid), 10)
	statBytes, err := os.ReadFile(filepath.Join("/proc", pidStr, "stat"))
	if err != nil {
		return ExecutionContext{}, nil, err
	}
	startTicks, kthread, err := parseProcStat(string(statBytes))
	if err != nil {
		return ExecutionContext{}, nil, err
	}
	ctx := ExecutionContext{
		TGID:          tgid,
		StartBoottime: startBoottime,
		StartTicks:    startTicks,
		ExecID:        execID,
		KernelThread:  kthread,
	}
	if kthread {
		return ctx, nil, nil
	}

	statusBytes, err := os.ReadFile(filepath.Join("/proc", pidStr, "status"))
	if err != nil {
		return ExecutionContext{}, nil, err
	}
	uid, gid, err := parseProcStatusCreds(string(statusBytes))
	if err != nil {
		return ExecutionContext{}, nil, err
	}
	ctx.UID = uid
	ctx.GID = gid

	var exeSt unix.Stat_t
	if err := unix.Stat(filepath.Join("/proc", pidStr, "exe"), &exeSt); err != nil {
		return ExecutionContext{}, nil, err
	}
	ctx.ExeDev = EncodeKernelDev(unix.Major(uint64(exeSt.Dev)), unix.Minor(uint64(exeSt.Dev)))
	ctx.ExeIno = exeSt.Ino

	var mntSt, netSt, pidSt unix.Stat_t
	if err := unix.Stat(filepath.Join("/proc", pidStr, "ns", "mnt"), &mntSt); err != nil {
		return ExecutionContext{}, nil, err
	}
	if err := unix.Stat(filepath.Join("/proc", pidStr, "ns", "net"), &netSt); err != nil {
		return ExecutionContext{}, nil, err
	}
	if err := unix.Stat(filepath.Join("/proc", pidStr, "ns", "pid"), &pidSt); err != nil {
		return ExecutionContext{}, nil, err
	}
	ctx.MntNSInum = mntSt.Ino
	ctx.NetNSInum = netSt.Ino
	ctx.PIDNSInum = pidSt.Ino

	mountBytes, err := os.ReadFile(filepath.Join("/proc", pidStr, "mountinfo"))
	if err != nil {
		return ExecutionContext{}, nil, err
	}
	mounts, rootMntID, err := ParseMountInfo(string(mountBytes))
	if err != nil {
		return ExecutionContext{}, nil, err
	}
	ctx.RootMntID = rootMntID
	ctx.AsyncSubmitter = HasAsyncSubmitter(tgid)
	return ctx, mounts, nil
}

func readConfinedFlatpakInfo(tgid uint32) (string, error) {
	pidStr := strconv.FormatUint(uint64(tgid), 10)
	rootFD, err := unix.Open(filepath.Join("/proc", pidStr, "root"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(rootFD)

	how := &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	}
	fd, err := unix.Openat2(rootFD, ".flatpak-info", how)
	if errors.Is(err, unix.ENOSYS) {
		fd, err = unix.Openat(rootFD, ".flatpak-info", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) {
			return "", nil
		}
		return "", err
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if (st.Mode & unix.S_IFMT) != unix.S_IFREG {
		return "", errors.New(".flatpak-info is not a regular file")
	}
	raw, err := readBoundedFD(fd, maxProcReadSize)
	if err != nil {
		return "", err
	}
	return ParseFlatpakInfo(string(raw))
}

func readAppImageEnvAndBacking(tgid uint32) (appImageEnv, appDirEnv string, backing *FileIdentity) {
	pidStr := strconv.FormatUint(uint64(tgid), 10)
	envFD, err := unix.Open(filepath.Join("/proc", pidStr, "environ"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", "", nil
	}
	raw, readErr := readBoundedFD(envFD, maxProcReadSize)
	_ = unix.Close(envFD)
	if readErr != nil || len(raw) == 0 {
		return "", "", nil
	}
	for _, entry := range bytes.Split(raw, []byte{0}) {
		s := string(entry)
		if strings.HasPrefix(s, "APPIMAGE=") {
			appImageEnv = strings.TrimPrefix(s, "APPIMAGE=")
		} else if strings.HasPrefix(s, "APPDIR=") {
			appDirEnv = strings.TrimPrefix(s, "APPDIR=")
		}
	}
	cleanImg := path.Clean(strings.TrimSpace(appImageEnv))
	if !strings.HasPrefix(cleanImg, "/") {
		return appImageEnv, appDirEnv, nil
	}
	var st unix.Stat_t
	relPath := strings.TrimPrefix(cleanImg, "/")
	if relPath != "" {
		rootFD, openErr := unix.Open(filepath.Join("/proc", pidStr, "root"), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if openErr == nil {
			statErr := unix.Fstatat(rootFD, relPath, &st, unix.AT_SYMLINK_NOFOLLOW)
			_ = unix.Close(rootFD)
			if statErr == nil {
				return appImageEnv, appDirEnv, &FileIdentity{
					Dev:     EncodeKernelDev(unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))),
					Ino:     st.Ino,
					Regular: (st.Mode & unix.S_IFMT) == unix.S_IFREG,
				}
			}
		}
	}
	if err := unix.Lstat(cleanImg, &st); err == nil {
		return appImageEnv, appDirEnv, &FileIdentity{
			Dev:     EncodeKernelDev(unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))),
			Ino:     st.Ino,
			Regular: (st.Mode & unix.S_IFMT) == unix.S_IFREG,
		}
	}
	return appImageEnv, appDirEnv, nil
}

// SampleProcessMaterial collects a bracketed before/after /proc sample along
// with confined Flatpak, Snap and Registered-AppImage verification material.
func SampleProcessMaterial(tgid uint32, startBoottime, execID uint64) (RawProcessMaterial, error) {
	before, mounts, err := SampleExecutionContext(tgid, startBoottime, execID)
	if err != nil {
		return RawProcessMaterial{}, err
	}
	if before.KernelThread {
		return RawProcessMaterial{Before: before, After: before}, nil
	}
	pidStr := strconv.FormatUint(uint64(tgid), 10)
	exePath, err := os.Readlink(filepath.Join("/proc", pidStr, "exe"))
	if err != nil {
		return RawProcessMaterial{}, err
	}
	flatpakID, flatpakErr := readConfinedFlatpakInfo(tgid)
	appImgEnv, appDirEnv, backing := readAppImageEnvAndBacking(tgid)
	after, _, err := SampleExecutionContext(tgid, startBoottime, execID)
	if err != nil {
		return RawProcessMaterial{}, err
	}
	return RawProcessMaterial{
		Before:          before,
		After:           after,
		ExePath:         exePath,
		FlatpakAppID:    flatpakID,
		FlatpakInfoErr:  flatpakErr,
		AppImageEnv:     appImgEnv,
		AppDirEnv:       appDirEnv,
		AppImageBacking: backing,
		Mounts:          mounts,
	}, nil
}

type pidIncarnation struct {
	tgid  uint32
	start uint64
}

// SyncActorRecords processes synchronous BPF actor send records in deterministic
// order, detecting superseded exec generations under the same (TGID, Start),
// exited cold actors, and live async submitters.
func (l *IdentityLedger) SyncActorRecords(records map[ActorKey]ActorEvidence, processed map[ActorKey]bool) {
	maxExecByPID := make(map[pidIncarnation]uint64)
	keys := make([]ActorKey, 0, len(records))
	for k := range records {
		inc := pidIncarnation{tgid: k.TGID, start: k.Start}
		if k.Exec > maxExecByPID[inc] {
			maxExecByPID[inc] = k.Exec
		}
		if processed != nil && processed[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Cookie != keys[j].Cookie {
			return keys[i].Cookie < keys[j].Cookie
		}
		if keys[i].TGID != keys[j].TGID {
			return keys[i].TGID < keys[j].TGID
		}
		if keys[i].Start != keys[j].Start {
			return keys[i].Start < keys[j].Start
		}
		return keys[i].Exec < keys[j].Exec
	})

	for _, k := range keys {
		ev := records[k]
		if processed != nil {
			processed[k] = true
		}
		actorKey := ActorIdentityKey{TGID: k.TGID, StartBoottime: k.Start, ExecID: k.Exec}
		if existing, ok := l.actors[actorKey]; ok {
			if HasAsyncSubmitter(k.TGID) {
				l.ObserveUnobservableSubmitter(k.Cookie)
				continue
			}
			_ = existing
			l.ObserveWarmSend(k, ev)
			continue
		}
		liveExec := maxExecByPID[pidIncarnation{tgid: k.TGID, start: k.Start}]
		mat, err := SampleProcessMaterial(k.TGID, k.Start, liveExec)
		if err != nil {
			if os.IsNotExist(err) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
				l.ObserveColdUnretained(k, ev)
				continue
			}
			l.recordFailureMetric(ReasonContextChanged)
			l.applyContributor(k.Cookie, actorKey, nil, ReasonContextChanged)
			continue
		}
		l.EnrichActor(k, ev, mat)
	}
}
