package updates

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const LatestReleaseAPIURL = "https://api.github.com/repositories/1418987447/releases/latest"

// Check retrieves the existing update offer by numeric repository ID.
func Check(ctx context.Context, version, architecture string) (*Offer, error) {
	return checkURL(ctx, LatestReleaseAPIURL, http.DefaultClient, version, architecture)
}

func checkURL(ctx context.Context, url string, client *http.Client, version, architecture string) (*Offer, error) {
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
	var release map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&release); err != nil {
		return nil, err
	}
	return OfferFrom(release, version, architecture), nil
}
