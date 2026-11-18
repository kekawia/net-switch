package control

import "context"

type shutdownReason uint8

const (
	ownerShutdown shutdownReason = iota
	serviceShutdown
	packageUpgradeShutdown
)

func (c *Core) Shutdown(ctx context.Context) error {
	return c.shutdown(ctx, ownerShutdown)
}

// ShutdownForService preserves only the Windows update's durable routing
// choice. An owner's Quit still commits an explicit stop through Shutdown.
func (c *Core) ShutdownForService(ctx context.Context) error {
	return c.shutdown(ctx, serviceShutdown)
}

// ShutdownForPackageUpgrade stops the engine without treating replacement of
// the installed files as an owner's Stop. The boot-scoped journal remains
// authoritative, including an accepted Stop that arrived before this boundary.
func (c *Core) ShutdownForPackageUpgrade(ctx context.Context) error {
	return c.shutdown(ctx, packageUpgradeShutdown)
}

func (c *Core) commitShutdownIntent(reason shutdownReason) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	next := routingIntent{preserveUpdate: reason == serviceShutdown}
	if reason == packageUpgradeShutdown {
		next.wanted = c.WantsRouting()
	}
	return c.commitIntent(next)
}
