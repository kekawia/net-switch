//go:build linux

package linuxui

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
)

var chromiumCandidates = []string{
	"chromium",
	"chromium-browser",
	"google-chrome-stable",
	"google-chrome",
	"brave-browser",
	"microsoft-edge-stable",
	"vivaldi-stable",
}

// OpenAppWindow displays the pairing code notification (when non-empty) and
// opens pairURL in a dedicated Chromium --app window when available, falling
// back to xdg-open. Only loopback http://127.0.0.1 or http://localhost URLs are accepted.
func OpenAppWindow(ctx context.Context, pairURL, code, owner string) error {
	u, err := validateLoopbackPairURL(pairURL)
	if err != nil {
		return err
	}
	if code != "" {
		msg := fmt.Sprintf("Enter %s in Net Switch. This code expires in two minutes.", code)
		if owner != "" {
			msg = fmt.Sprintf("Net Switch is set up for %s. Enter %s in Net Switch. This code expires in two minutes.", owner, code)
		}
		_ = SendNotification(ctx, "Connect to Net Switch", msg, 120000)
	}

	target := u.String()
	for _, bin := range chromiumCandidates {
		if path, err := exec.LookPath(bin); err == nil && path != "" {
			cmd := exec.Command(path, "--app="+target)
			if err := cmd.Start(); err == nil {
				go func() { _ = cmd.Wait() }()
				return nil
			}
		}
	}

	cmd := exec.Command("xdg-open", target)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch browser for Net Switch: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

func validateLoopbackPairURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("invalid Net Switch URL: %w", err)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("refusing non-http Net Switch URL scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host != "127.0.0.1" && host != "localhost" {
		return nil, fmt.Errorf("refusing non-loopback Net Switch host %q", host)
	}
	return u, nil
}
