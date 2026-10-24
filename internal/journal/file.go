package journal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const RecordLimit = 1 << 20

type envelope struct {
	Record  json.RawMessage `json:"record,omitempty"`
	Records json.RawMessage `json:"records,omitempty"`
	Hash    string          `json:"sha256"`
}

// FileStore is an fsynced append journal. The platform supplies directory
// durability and creates the parent with the required ACL/mode. SyncParent is
// required so a newly created journal cannot disappear after an OS mutation.
type FileStore struct {
	Path       string
	SyncParent func(string) error
	mu         sync.Mutex
	dirty      bool
}

// Records reads the journal as its owner: a torn final frame is truncated away
// and the file synced, so the next append starts on a complete frame.
func (f *FileStore) Records() ([]Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.OpenFile(f.Path, os.O_RDWR, 0600)
	if errors.Is(err, os.ErrNotExist) {
		f.dirty = false
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	frames, err := scanFrames(file)
	if err != nil {
		return nil, err
	}
	if frames.torn {
		if err := file.Truncate(frames.complete); err != nil {
			return nil, err
		}
		if err := file.Sync(); err != nil {
			return nil, err
		}
	}
	f.dirty = false
	return frames.records, nil
}

// ReadOnly lists a journal's records without taking ownership of the file: it
// opens the journal for reading only and leaves a torn final frame in place
// for the owner to recover. Corruption before another complete frame is an
// error, as it is for the owner. A missing journal has no records.
func ReadOnly(path string) ([]Record, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	frames, err := scanFrames(file)
	if err != nil {
		return nil, err
	}
	return frames.records, nil
}

type scannedFrames struct {
	records  []Record
	complete int64 // bytes holding complete, valid frames
	torn     bool  // an incomplete or invalid final frame follows them
}

// scanFrames decodes the newline-delimited checksummed frames of a journal,
// bounding each line by RecordLimit before it is held whole. It is the one
// reader of the on-disk format; the owner's recovery and read-only inspection
// differ only in what they do about a torn tail.
func scanFrames(file io.Reader) (scannedFrames, error) {
	var out scannedFrames
	r := bufio.NewReaderSize(file, 4096)
	for {
		var line []byte
		oversize := false
		var err error
		for {
			part, readErr := r.ReadSlice('\n')
			if len(line)+len(part) > RecordLimit {
				oversize = true
			}
			if !oversize {
				line = append(line, part...)
			}
			err = readErr
			if err != bufio.ErrBufferFull {
				break
			}
		}
		if err == io.EOF {
			out.torn = len(line) > 0 || oversize
			return out, nil
		}
		if err != nil {
			return out, err
		}
		batch, decodeErr := decodeRecords(line)
		if oversize {
			decodeErr = errors.New("journal record exceeds limit")
		}
		if decodeErr != nil {
			// A torn write may include its newline. Only the final invalid
			// frame is recoverable; corruption before another line is fatal.
			if _, peekErr := r.Peek(1); peekErr != io.EOF {
				return out, decodeErr
			}
			out.torn = true
			return out, nil
		}
		out.records = append(out.records, batch...)
		out.complete += int64(len(line))
	}
}

func decodeRecords(line []byte) ([]Record, error) {
	var e envelope
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing journal data")
	}
	if (e.Record == nil) == (e.Records == nil) {
		return nil, errors.New("journal frame needs one record or one record batch")
	}
	raw := e.Record
	if e.Records != nil {
		raw = e.Records
	}
	sum := sha256.Sum256(raw)
	if e.Hash != hex.EncodeToString(sum[:]) {
		return nil, errors.New("journal checksum mismatch")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var records []Record
	if e.Record != nil {
		var record Record
		if err := d.Decode(&record); err != nil {
			return nil, err
		}
		records = []Record{record}
	} else if err := d.Decode(&records); err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, errors.New("empty journal record batch")
	}
	return records, nil
}

func (f *FileStore) Append(record Record) error {
	return f.AppendBatch([]Record{record})
}

// One checksummed line frames the whole batch. Merely concatenating record
// lines before one sync would allow a torn batch to look like interior
// corruption. A partial final frame can instead be discarded as a unit.
func encodeRecords(records []Record) ([]byte, error) {
	var value any = records
	if len(records) == 1 {
		value = records[0] // Keep the original single-record on-disk format.
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	e := envelope{Hash: hex.EncodeToString(sum[:])}
	if len(records) == 1 {
		e.Record = raw
	} else {
		e.Records = raw
	}
	line, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if len(line) > RecordLimit {
		return nil, errors.New("journal frame exceeds limit")
	}
	return line, nil
}

func (f *FileStore) AppendBatch(records []Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(records) == 0 {
		return nil
	}
	if f.dirty {
		return errors.New("journal needs tail recovery")
	}
	if f.SyncParent == nil {
		return errors.New("journal directory durability hook required")
	}
	line, err := encodeRecords(records)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(f.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	f.dirty = true
	n, writeErr := file.Write(line)
	if writeErr == nil && n != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if err := f.SyncParent(filepath.Dir(f.Path)); err != nil {
		return err
	}
	f.dirty = false
	return nil
}

// ClearRetired is used only under the engine's lifetime lock, after all
// recorded objects have been retired. Truncation is safe there: a crash leaves
// either historical removed records or an empty journal, never lost ownership.
func (f *FileStore) ClearRetired() error {
	records, err := f.Records()
	if err != nil {
		return err
	}
	live := map[string]bool{}
	for _, r := range records {
		if r.Phase == "removed" {
			delete(live, r.ID)
		} else {
			live[r.ID] = true
		}
	}
	if len(live) != 0 {
		return errors.New("cannot compact live ownership records")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	file, err := os.OpenFile(f.Path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = file.Sync()
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	return f.SyncParent(filepath.Dir(f.Path))
}
