package netswitch

import (
	"embed"
	"encoding/json"
	"strings"

	"github.com/AyoubAchour/net-switch/internal/buildinfo"
	"github.com/AyoubAchour/net-switch/internal/updates"
)

// UI contains the unchanged UI used by the Node application and C# tray.
//
//go:embed ui/index.html ui/app.js ui/styles.css ui/favicon.svg
var UI embed.FS

//go:embed package.json
var manifest []byte

func AppVersion() string {
	if v := strings.TrimPrefix(strings.TrimSpace(buildinfo.String()), "v"); updates.ParseVersion(v) != nil {
		return v
	}
	var m struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(manifest, &m); err != nil {
		panic(err)
	}
	return m.Version
}
