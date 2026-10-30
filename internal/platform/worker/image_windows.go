package worker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const imagePrefix = "NetSwitchWorker-"
const privateDirectorySDDL = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
const privateImageSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;WD)S:(ML;;NW;;;HI)"

var errForeignWorkerDirectory = errors.New("not an owned worker directory")

type imageOwner struct {
	PID     uint32
	Created uint64
}
type imagePolicy struct {
	Filters [2]windows.GUID
}
type workerImage struct {
	directory, executable string
	policy                imagePolicy
}

func processCreated(h windows.Handle) (uint64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime), nil
}

var imageRoot = func() (string, error) { return windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0) }

func secureCreate(path, sddl string) (*os.File, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func writeImageRecord(path string, value any) error {
	f, err := secureCreate(path, privateDirectorySDDL)
	if err != nil {
		return err
	}
	err = json.NewEncoder(f).Encode(value)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func newWorkerImage(source string) (_ *workerImage, err error) {
	root, err := imageRoot()
	if err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(random[:])
	created, err := processCreated(windows.CurrentProcess())
	if err != nil {
		return nil, err
	}
	base := fmt.Sprintf("%s%d-%d-%s", imagePrefix, windows.GetCurrentProcessId(), created, nonce)
	w := &workerImage{directory: filepath.Join(root, base)}
	w.executable = filepath.Join(w.directory, "worker.exe")
	sd, err := windows.SecurityDescriptorFromString(privateDirectorySDDL)
	if err != nil {
		return nil, err
	}
	name, _ := windows.UTF16PtrFromString(w.directory)
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	if err = windows.CreateDirectory(name, &sa); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, w.removeFiles())
		}
	}()
	for i := range w.policy.Filters {
		if w.policy.Filters[i], err = windows.GenerateGUID(); err != nil {
			return nil, err
		}
	}
	if err = writeImageRecord(filepath.Join(w.directory, "policy.json"), w.policy); err != nil {
		return nil, err
	}
	in, err := os.Open(source)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	out, err := secureCreate(w.executable, privateImageSDDL)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	err = errors.Join(err, out.Close())
	if err != nil {
		return nil, err
	}
	return w, nil
}

func (w *workerImage) removeFiles() error {
	// Never recurse, follow a directory link, or delete an arbitrary recorded
	// path. All names are fixed children of the directory we created.
	for _, name := range []string{"worker.exe", "child.json", "policy.json"} {
		if err := os.Remove(filepath.Join(w.directory, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Remove(w.directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (w *workerImage) removeExecutable() error {
	if err := os.Remove(w.executable); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func ownerAlive(owner imageOwner) (bool, error) {
	if owner.PID == 0 || owner.Created == 0 {
		return false, fmt.Errorf("invalid worker image owner")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, owner.PID)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer windows.CloseHandle(h)
	created, err := processCreated(h)
	if err != nil {
		return false, err
	}
	if created != owner.Created {
		return false, nil
	}
	state, err := windows.WaitForSingleObject(h, 0)
	return state == uint32(windows.WAIT_TIMEOUT), err
}

func readImageRecord(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(io.LimitReader(f, 4096)).Decode(v)
}

func trustedImageDirectory(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return errForeignWorkerDirectory
		}
		return err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errForeignWorkerDirectory
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	want, err := windows.SecurityDescriptorFromString(privateDirectorySDDL)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	expected, _, err := want.DACL()
	if err != nil {
		return err
	}
	if owner == nil || owner.String() != "S-1-5-32-544" || control&windows.SE_DACL_PROTECTED == 0 || acl == nil || acl.AceCount != expected.AceCount {
		return errForeignWorkerDirectory
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var actualACE, wantACE *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &actualACE); err != nil {
			return err
		}
		if err := windows.GetAce(expected, i, &wantACE); err != nil {
			return err
		}
		if actualACE.Header.AceType != wantACE.Header.AceType || actualACE.Header.AceFlags != wantACE.Header.AceFlags || actualACE.Mask != wantACE.Mask || (*windows.SID)(unsafe.Pointer(&actualACE.SidStart)).String() != (*windows.SID)(unsafe.Pointer(&wantACE.SidStart)).String() {
			return errForeignWorkerDirectory
		}
	}
	return nil
}

func recoverWorkerImages() error {
	root, err := imageRoot()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), imagePrefix) {
			continue
		}
		if _, err := imageDirectoryOwner(entry.Name()); err != nil {
			continue
		}
		directory := filepath.Join(root, entry.Name())
		if err := recoverWorkerImage(directory); err != nil && !errors.Is(err, errForeignWorkerDirectory) && !errors.Is(err, os.ErrNotExist) {
			failures = append(failures, fmt.Errorf("recover %s: %w", directory, err))
		}
	}
	return errors.Join(failures...)
}

func recoverWorkerImage(directory string) error {
	if err := trustedImageDirectory(directory); err != nil {
		return err
	}
	owner, err := imageDirectoryOwner(filepath.Base(directory))
	if err != nil {
		return err
	}
	parentAlive, err := ownerAlive(owner)
	if err != nil {
		return err
	}
	var child imageOwner
	if err := readImageRecord(filepath.Join(directory, "child.json"), &child); err == nil {
		if alive, err := ownerAlive(child); err != nil || alive {
			if err != nil && parentAlive {
				return nil
			}
			return err
		}
	} else {
		if parentAlive {
			return nil
		} // creation/record write may still be in progress
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	w := &workerImage{directory: directory, executable: filepath.Join(directory, "worker.exe")}
	if err := readImageRecord(filepath.Join(directory, "policy.json"), &w.policy); err != nil {
		// No filter is created until a complete, durable policy record exists.
		if _, imageErr := os.Stat(w.executable); !errors.Is(imageErr, os.ErrNotExist) {
			return err
		}
		return w.removeFiles()
	}
	// If another process still maps this unique image, keep its fence. Remove
	// the image before the rules, retaining the durable keys on any failure.
	if err := w.removeExecutable(); err != nil {
		return err
	}
	if err := removeImageFence(w); err != nil {
		return err
	}
	return w.removeFiles()
}

// The owner incarnation is part of the directory name, so a crash between
// creating the directory and writing the policy record is recoverable too.
func imageDirectoryOwner(name string) (imageOwner, error) {
	if !strings.HasPrefix(name, imagePrefix) {
		return imageOwner{}, fmt.Errorf("not a worker directory")
	}
	parts := strings.Split(strings.TrimPrefix(name, imagePrefix), "-")
	if len(parts) != 3 {
		return imageOwner{}, fmt.Errorf("invalid worker directory identity")
	}
	pid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || pid == 0 {
		return imageOwner{}, fmt.Errorf("invalid worker owner PID")
	}
	created, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || created == 0 {
		return imageOwner{}, fmt.Errorf("invalid worker owner creation time")
	}
	if b, err := hex.DecodeString(parts[2]); err != nil || len(b) != 16 {
		return imageOwner{}, fmt.Errorf("invalid worker directory nonce")
	}
	return imageOwner{uint32(pid), created}, nil
}
