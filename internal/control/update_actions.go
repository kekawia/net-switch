package control

import (
	"context"

	js "github.com/kekawia/net-switch/internal/jsvalue"
)

func (c *Core) updateApplying() bool {
	if c.op.Updater == nil {
		return false
	}
	status := c.op.Updater.Status()
	if status == nil {
		return false
	}
	switch status.Phase {
	case "preparing", "snapshotted", "applying", "checking", "rolling-back":
		return true
	}
	return false
}

// RestoreUpdateIntent changes no engine state and does not reset crash budgets.
// The latest accepted owner choice wins over the installer's earlier snapshot.
func (c *Core) RestoreUpdateIntent(operation string, wanted bool) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	if c.op.Journal != nil {
		if saved, ok := c.op.Journal.Values()["updateIntent"].(map[string]any); ok && saved["operation"] == operation {
			if value, ok := saved["wanted"].(bool); ok {
				wanted = value
			}
		}
	}
	return c.commitIntent(routingIntent{wanted: wanted})
}

func (c *Core) updateAction(ctx context.Context, path string, body map[string]any) (any, error) {
	switch path {
	case "/api/update/dismiss":
		if js.Text(body["version"]) == "" {
			return nil, bad("Choose which update to skip, then try again.")
		}
		if err := c.save(map[string]any{"skippedUpdate": body["version"]}); err != nil {
			return nil, err
		}
	case "/api/update/check":
		if c.op.Mode == "proxy" {
			return nil, bad("Test mode doesn’t check for updates.")
		}
		result, err := c.CheckUpdate(ctx, true)
		if err != nil {
			c.log("could not check for updates: %v", err)
		}
		state := c.State()
		var version any
		c.mu.Lock()
		if c.offer != nil {
			version = c.offer.Version
		}
		c.mu.Unlock()
		state["check"] = map[string]any{"result": result, "version": version}
		return state, nil
	case "/api/update/apply":
		version := js.Text(body["version"])
		c.mu.Lock()
		offer := c.offer
		c.mu.Unlock()
		retry := false
		if c.op.Updater != nil {
			if status := c.op.Updater.Status(); status != nil && status.Version == version && (status.Phase == "rolled-back" || status.Phase == "download-error") {
				retry = true
			}
		}
		if !retry && (offer == nil || offer.Version != version) {
			return nil, bad("Check for updates again, then try again.")
		}
		if offer != nil && offer.PackageManager {
			return nil, bad("Update with your package manager.")
		}
		if c.op.Updater == nil || c.op.Mode == "proxy" {
			return nil, bad("Install Net Switch before updating it here.")
		}
		if err := c.op.Updater.Start(ctx, version); err != nil {
			c.log("start update: %v", err)
			return nil, bad("Couldn’t start the update. Try again.")
		}
	case "/api/update/status-dismiss":
		if c.op.Updater == nil {
			return nil, bad("There is no update to dismiss.")
		}
		status := c.op.Updater.Status()
		if status == nil || status.Operation != js.Text(body["operation"]) || status.Busy() {
			return nil, bad("This update can’t be dismissed right now.")
		}
		if err := c.save(map[string]any{"skippedUpdate": status.Version}); err != nil {
			return nil, err
		}
		if err := c.op.Updater.Dismiss(status.Operation); err != nil {
			return nil, err
		}
	default:
		return nil, routeError("POST", path)
	}
	return c.State(), nil
}
