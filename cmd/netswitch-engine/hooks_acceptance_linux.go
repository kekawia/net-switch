//go:build linux && acceptance

package main

import (
	"github.com/kekawia/net-switch/internal/engine"
	"github.com/kekawia/net-switch/internal/engine/linux"
	"github.com/kekawia/net-switch/internal/engine/protocol"
)

func installTestHooks(p *linux.Platform, e *engine.Engine, s *protocol.Server) {
	p.InstallAcceptanceHooks(e, s)
}
