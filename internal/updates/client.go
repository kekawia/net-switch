package updates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

var ErrInstallerIntegrity = errors.New("installer does not match the signed manifest")
var ErrSignatureCheck = errors.New("update metadata verification failed")

type Client struct {
	HTTP     *http.Client
	Root     string
	Platform string
	Now      func() time.Time
}

func (c *Client) root() string {
	if c.Root != "" {
		return c.Root
	}
	return RootPublicKey
}
func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}
func (c *Client) platform() string {
	if c.Platform != "" {
		return c.Platform
	}
	return runtime.GOOS
}

func (c *Client) httpClient() *http.Client {
	var client http.Client
	if c.HTTP != nil {
		client = *c.HTTP
	}
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 5 || request.URL.Scheme != "https" || request.URL.User != nil || request.URL.Port() != "" {
			return errors.New("update download redirect refused")
		}
		switch request.URL.Hostname() {
		case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
			return nil
		}
		return errors.New("update download left GitHub's release hosts")
	}
	return &client
}

func releaseVersion(release map[string]any, current string) string {
	if release == nil || release["draft"] == true || release["prerelease"] == true {
		return ""
	}
	tag, _ := release["tag_name"].(string)
	version := strings.TrimPrefix(tag, "v")
	if tag != "v"+version || !CanonicalVersion(version) || !CanonicalVersion(current) || !IsNewer(version, current) {
		return ""
	}
	if release["html_url"] != ReleaseBase+"tag/"+tag {
		return ""
	}
	return version
}

func releaseAsset(release map[string]any, version, name string) (string, error) {
	want := ReleaseBase + "download/v" + version + "/" + name
	assets, _ := release["assets"].([]any)
	found := false
	for _, entry := range assets {
		asset, _ := entry.(map[string]any)
		if asset["name"] != name {
			continue
		}
		if found || asset["browser_download_url"] != want {
			return "", errors.New("ambiguous or invalid update asset")
		}
		found = true
	}
	if !found {
		return "", fmt.Errorf("release is missing %s", name)
	}
	return want, nil
}

func (c *Client) Check(ctx context.Context, current, architecture string) (*Offer, error) {
	if architecture != "x64" && architecture != "arm64" {
		return nil, errors.New("unsupported update architecture")
	}
	release, err := fetchRelease(ctx, LatestReleaseAPIURL, c.httpClient(), current)
	if err != nil {
		return nil, err
	}
	version := releaseVersion(release, current)
	if version == "" {
		return nil, nil
	}
	page := ReleaseBase + "tag/v" + version
	if c.platform() == "linux" {
		return &Offer{Version: version, Page: page, PackageManager: true}, nil
	}
	if c.platform() != "windows" {
		return nil, errors.New("updates are unsupported on this platform")
	}
	var bundle Bundle
	for _, item := range []struct {
		name   string
		target *[]byte
	}{
		{"netswitch-release-key.json", &bundle.Key},
		{"netswitch-release-key.json.minisig", &bundle.KeySignature},
		{"update-manifest-" + architecture + ".json", &bundle.Manifest},
		{"update-manifest-" + architecture + ".json.minisig", &bundle.ManifestSignature},
	} {
		url, err := releaseAsset(release, version, item.name)
		if err != nil {
			return nil, err
		}
		*item.target, err = c.metadata(ctx, url)
		if err != nil {
			return nil, err
		}
	}
	manifest, err := VerifyBundle(c.root(), bundle, current, architecture, c.now())
	if err != nil {
		return nil, errors.Join(ErrSignatureCheck, err)
	}
	if manifest.Version != version {
		return nil, errors.New("signed version does not match the release")
	}
	url, err := releaseAsset(release, version, "NetSwitch-Setup-"+version+"-"+architecture+".exe")
	if err != nil || url != manifest.URL {
		return nil, errors.New("signed installer is missing from the release")
	}
	return &Offer{Version: version, Page: page, Installer: manifest.URL, Bundle: &bundle}, nil
}

func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "NetSwitch signed updater")
	response, err := c.httpClient().Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, fmt.Errorf("update download answered %d", response.StatusCode)
	}
	return response, nil
}

func (c *Client) metadata(ctx context.Context, url string) ([]byte, error) {
	response, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, MaxMetadataSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > MaxMetadataSize {
		return nil, errors.New("update metadata exceeds its size limit")
	}
	return raw, nil
}

type progressWriter struct {
	writer   io.Writer
	bytes    int64
	progress func(int64)
}

func (w *progressWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	w.bytes += int64(n)
	if w.progress != nil {
		w.progress(w.bytes)
	}
	return n, err
}

func (c *Client) Download(ctx context.Context, manifest Manifest, target io.Writer, progress func(int64)) error {
	if manifest.Size <= 0 || manifest.Size > MaxInstallerSize || manifest.URL != InstallerURL(manifest.Version, manifest.Architecture) {
		return ErrInstallerIntegrity
	}
	response, err := c.get(ctx, manifest.URL)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	hash := sha256.New()
	writer := &progressWriter{writer: io.MultiWriter(target, hash), progress: progress}
	if _, err := io.Copy(writer, io.LimitReader(response.Body, manifest.Size+1)); err != nil {
		return err
	}
	if writer.bytes != manifest.Size || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), manifest.SHA256) {
		return ErrInstallerIntegrity
	}
	return nil
}
