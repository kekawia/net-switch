//go:build linux

// Package linuxui implements the Linux desktop tray icon, D-Bus notifications,
// and Chromium-app pairing window launcher for Net Switch.
package linuxui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// CanConnectSessionBus reports whether a user D-Bus session bus is reachable.
// Uses a private non-shared connection so headless sessions without D-Bus
// degrade cleanly without polluting godbus's package-level singleton.
func CanConnectSessionBus(ctx context.Context) bool {
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	bus, err := dbus.ConnectSessionBus(dbus.WithContext(cctx))
	if err != nil {
		return false
	}
	_ = bus.Close()
	return true
}

// HasStatusNotifierWatcher reports whether KDE/Freedesktop StatusNotifierWatcher
// is registered on the session bus.
func HasStatusNotifierWatcher(ctx context.Context) bool {
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	bus, err := dbus.ConnectSessionBus(dbus.WithContext(cctx))
	if err != nil {
		return false
	}
	defer bus.Close()

	for _, name := range []string{"org.kde.StatusNotifierWatcher", "org.freedesktop.StatusNotifierWatcher"} {
		var owned bool
		if err := bus.BusObject().CallWithContext(cctx, "org.freedesktop.DBus.NameHasOwner", 0, name).Store(&owned); err == nil && owned {
			return true
		}
	}
	return false
}

// SendNotification delivers a transient freedesktop desktop notification on a
// private session D-Bus connection.
func SendNotification(ctx context.Context, title, body string, timeoutMS int32) error {
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		return fmt.Errorf("session D-Bus is unavailable")
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	bus, err := dbus.ConnectSessionBus(dbus.WithContext(cctx))
	if err != nil {
		return fmt.Errorf("connect session D-Bus: %w", err)
	}
	defer bus.Close()

	var id uint32
	err = bus.Object("org.freedesktop.Notifications", "/org/freedesktop/Notifications").
		CallWithContext(
			cctx,
			"org.freedesktop.Notifications.Notify",
			0,
			"Net Switch",
			uint32(0),
			"network-workgroup",
			title,
			body,
			[]string{},
			map[string]dbus.Variant{"transient": dbus.MakeVariant(true)},
			timeoutMS,
		).Store(&id)
	if err != nil {
		return fmt.Errorf("send desktop notification: %w", err)
	}
	return nil
}
