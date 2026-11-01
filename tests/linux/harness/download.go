package harness

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Pin is one verified download with an exact size and SHA-256 digest.
type Pin struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Download fetches a pinned resource with bounded retries and verifies its
// size and SHA-256 before returning the bytes.
func Download(ctx context.Context, pin Pin) ([]byte, error) {
	const maxAttempts = 4
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(attempt*5) * time.Second):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		data, err := get(ctx, pin.URL, pin.Size)
		if err == nil {
			err = Verify(data, pin)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, fmt.Errorf("download %s failed after %d attempts: %w", pin.URL, maxAttempts, lastErr)
}

func get(ctx context.Context, url string, size int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, size+1))
}

// Verify checks a download against its pin.
func Verify(data []byte, pin Pin) error {
	if int64(len(data)) != pin.Size {
		return fmt.Errorf("got %d bytes, the pin says %d", len(data), pin.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != pin.SHA256 {
		return fmt.Errorf("SHA-256 %s doesn't match the pinned %s", got, pin.SHA256)
	}
	return nil
}
