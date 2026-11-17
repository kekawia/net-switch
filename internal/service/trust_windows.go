package service

import "github.com/kekawia/net-switch/internal/wintrust"

func checkInstalledPath(path string, ancestor bool) error { return wintrust.Path(path, ancestor) }
