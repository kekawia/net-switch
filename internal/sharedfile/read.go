// Package sharedfile reads atomically published state without excluding its
// publisher. Only Windows sharing violations receive a bounded retry.
package sharedfile

import (
	"errors"
	"io"
	"os"
	"time"
)

// ReadFile reads at most limit+1 bytes so callers can enforce their existing
// size errors. A negative limit preserves an unbounded reader's semantics.
// Missing-file and permission errors are returned unchanged, without retry.
func ReadFile(path string, limit int64) ([]byte, error) {
	var data []byte
	err := retry(func() error {
		var err error
		data, err = readOnce(path, limit)
		return err
	})
	return data, err
}

// Open opens path for reading with the same sharing and retry as ReadFile,
// for callers that stream a large file, such as a log that is being appended
// to or rotated by renaming, without refusing its writer.
func Open(path string) (*os.File, error) {
	var file *os.File
	err := retry(func() error {
		var err error
		file, err = openFile(path)
		return err
	})
	return file, err
}

func retry(attempt func() error) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := attempt()
		if err == nil || !sharingViolation(err) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readOnce(path string, limit int64) ([]byte, error) {
	file, err := openFile(path)
	if err != nil {
		return nil, err
	} // keep *os.PathError for os.IsNotExist
	var reader io.Reader = file
	if limit >= 0 {
		reader = io.LimitReader(file, limit+1)
	}
	data, err := io.ReadAll(reader)
	return data, errors.Join(err, file.Close())
}
