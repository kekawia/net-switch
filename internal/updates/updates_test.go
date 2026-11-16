package updates

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOfferFromAcceptsCurrentOwnerAndRejectsRetiredOwner(t *testing.T) {
	valid := map[string]any{
		"tag_name": "v1.0.0",
		"html_url": "https://github.com/kekawia/net-switch/releases/tag/v1.0.0",
		"assets": []any{
			map[string]any{
				"name":                 "NetSwitch-Setup-1.0.0-x64.exe",
				"browser_download_url": "https://github.com/kekawia/net-switch/releases/download/v1.0.0/NetSwitch-Setup-1.0.0-x64.exe",
			},
		},
	}
	got := OfferFrom(valid, "0.3.2", "x64")
	if got == nil || got.Version != "1.0.0" {
		t.Fatalf("OfferFrom(valid) = %+v, want 1.0.0 offer", got)
	}

	retired := map[string]any{
		"tag_name": "v1.0.0",
		"html_url": "https://github.com/" + "AyoubAchour/net-switch/releases/tag/v1.0.0",
		"assets": []any{
			map[string]any{
				"name":                 "NetSwitch-Setup-1.0.0-x64.exe",
				"browser_download_url": "https://github.com/" + "AyoubAchour/net-switch/releases/download/v1.0.0/NetSwitch-Setup-1.0.0-x64.exe",
			},
		},
	}
	if got := OfferFrom(retired, "0.3.2", "x64"); got != nil {
		t.Fatalf("OfferFrom accepted retired owner URL: %+v", got)
	}
}

func TestCheckUsesNumericRepositoryIDAndHeaders(t *testing.T) {
	if LatestReleaseAPIURL != "https://api.github.com/repositories/1418987447/releases/latest" {
		t.Fatalf("LatestReleaseAPIURL = %q", LatestReleaseAPIURL)
	}
	var gotUA, gotAccept, gotVer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		gotAccept = r.Header.Get("Accept")
		gotVer = r.Header.Get("X-GitHub-Api-Version")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": "v1.1.0",
			"html_url": "https://github.com/kekawia/net-switch/releases/tag/v1.1.0",
			"assets": []any{
				map[string]any{
					"name":                 "NetSwitch-Setup-1.1.0-arm64.exe",
					"browser_download_url": "https://github.com/kekawia/net-switch/releases/download/v1.1.0/NetSwitch-Setup-1.1.0-arm64.exe",
				},
			},
		})
	}))
	defer srv.Close()

	offer, err := checkURL(context.Background(), srv.URL, srv.Client(), "1.0.0", "arm64")
	if err != nil {
		t.Fatalf("checkURL failed: %v", err)
	}
	if offer == nil || offer.Version != "1.1.0" {
		t.Fatalf("offer = %+v, want 1.1.0", offer)
	}
	if gotUA != "NetSwitch/1.0.0" || gotAccept != "application/vnd.github+json" || gotVer != "2022-11-28" {
		t.Fatalf("unexpected headers: UA=%q Accept=%q API=%q", gotUA, gotAccept, gotVer)
	}
}
