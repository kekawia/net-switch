//go:build lifecycle_test

package lifecycle

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/kekawia/net-switch/internal/updates"
)

// These one-shot faults exist only in explicitly instrumented CI installers.
func updateTestInstallerArgs(data string) []string {
	if CheckDirectory(data) == nil {
		if _, err := os.Stat(filepath.Join(data, "fault-update-reboot")); err == nil {
			return []string{"/NSUPDATEREBOOT=1"}
		}
	}
	return nil
}

func updateTestHealthError(data string) error {
	if CheckDirectory(data) == nil {
		path := filepath.Join(data, "fault-update-health")
		if os.Rename(path, path+".consumed") == nil {
			return errors.New("hosted fixture: update health failure after real installation")
		}
	}
	return nil
}

type updateFixtureTransport struct {
	base  *url.URL
	token string
}

type invalidUpdateFixture struct{}

func (invalidUpdateFixture) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("invalid protected update test source")
}

func (t updateFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	u := *request.URL
	u.Scheme, u.Host = t.base.Scheme, t.base.Host
	clone.URL = &u
	clone.Header.Set("X-Update-Fixture", t.token)
	return http.DefaultTransport.RoundTrip(clone)
}

// Only fault builds can substitute the network source through a protected file.
// The signed URLs, root key and all cryptographic/installer checks are unchanged.
func configureUpdateTestClient(data string, client *updates.Client) *updates.Client {
	if CheckDirectory(data) != nil {
		return client
	}
	var fixture struct {
		URL   string `json:"url"`
		Token string `json:"token"`
	}
	err := Read(filepath.Join(data, "update-fixture.json"), &fixture)
	if errors.Is(err, os.ErrNotExist) {
		return client
	}
	if err != nil {
		client.HTTP = &http.Client{Transport: invalidUpdateFixture{}}
		return client
	}
	base, err := url.Parse(fixture.URL)
	if err != nil || base.Scheme != "http" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || len(fixture.Token) != 64 {
		client.HTTP = &http.Client{Transport: invalidUpdateFixture{}}
		return client
	}
	client.HTTP = &http.Client{Transport: updateFixtureTransport{base: base, token: fixture.Token}}
	return client
}
