package desktop

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"

	"github.com/AyoubAchour/net-switch/internal/settings"
)

// TraySettings stores per-user desktop tray preferences.
type TraySettings struct {
	LineNotifications bool `json:"lineNotifications"`
}

// DefaultTraySettingsPath returns the per-user path to tray-settings.json.
func DefaultTraySettingsPath() (string, error) {
	if runtime.GOOS == "windows" {
		dir, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "Net Switch", "tray-settings.json"), nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netswitch", "tray-settings.json"), nil
}

// LoadTraySettings reads file and returns defaults (LineNotifications: true) if
// the file is missing or malformed.
func LoadTraySettings(file string) TraySettings {
	cfg := TraySettings{LineNotifications: true}
	b, err := os.ReadFile(file)
	if err != nil {
		return cfg
	}
	var saved map[string]any
	if err := json.Unmarshal(b, &saved); err != nil || saved == nil {
		return cfg
	}
	if v, ok := saved["lineNotifications"].(bool); ok {
		cfg.LineNotifications = v
	}
	return cfg
}

// Save writes cfg atomically with restricted file permissions.
func (s TraySettings) Save(file string) error {
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return settings.AtomicWrite(file, b, settings.Options{})
}
