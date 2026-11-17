package updates

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"runtime"
)

const LatestReleaseAPIURL = "https://api.github.com/repositories/1418987447/releases/latest"

// Check discovers an update from the numeric repository. Windows offers only
// installers whose manifest and rotating signing key verify against the root.
func Check(ctx context.Context, version, architecture string) (*Offer, error) {
	return (&Client{Platform: runtime.GOOS}).Check(ctx, version, architecture)
}

func fetchRelease(ctx context.Context, url string, client *http.Client, version string) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "NetSwitch/"+version)
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == 404 {
		return nil, nil
	}
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub answered %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 2<<20 {
		return nil, fmt.Errorf("release metadata exceeds its size limit")
	}
	var release map[string]any
	if err := json.Unmarshal(raw, &release); err != nil {
		return nil, err
	}
	return release, nil
}
