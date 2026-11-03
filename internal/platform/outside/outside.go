// Package outside tracks non-routed TCP connections and their byte counters
// on a five-second connection scan and one-second counter read cadence.
package outside

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strings"
)

type Entry struct {
	ID             string  `json:"id"`
	PID            uint32  `json:"pid"`
	Path           string  `json:"path"`
	AppID          string  `json:"appId,omitempty"`
	Local          string  `json:"local"`
	Created        string  `json:"created"`
	ProcessStarted string  `json:"processStarted,omitempty"`
	Down           *uint64 `json:"down"`
	Up             *uint64 `json:"up"`
}

type Line struct {
	Estats  bool    `json:"estats"`
	Outside []Entry `json:"outside"`
}

// RescanEvery is how often the full connection list is refreshed, in seconds.
const RescanEvery = 5

// Local addresses that aren't on a physical line: loopback, unbound, and the
// routing engine's own tunnel.
var skipLocal = map[string]bool{"127.0.0.1": true, "0.0.0.0": true, "198.18.0.1": true}

// Remote addresses on a local network, loopback, link-local, multicast and
// broadcast.
var privateRemote = regexp.MustCompile(`^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|22[4-9]\.|23[0-9]\.|255\.)`)

func Ignored(local, remote string) bool {
	return skipLocal[local] || privateRemote.MatchString(remote)
}

// ConnectionID includes the owner PID and creation marker so a reused 4-tuple
// is never mistaken for an earlier connection.
func ConnectionID(local string, localPort uint16, remote string, remotePort uint16, pid uint32, created string) string {
	return fmt.Sprintf("%s:%d>%s:%d|%d|%s", local, localPort, remote, remotePort, pid, created)
}

type Connection[Row any] struct {
	Established bool
	Local       [4]byte
	LocalPort   uint16
	Remote      [4]byte
	RemotePort  uint16
	PID         uint32
	Created     string
	Row         Row
}

type System[Row any] struct {
	Estats       bool
	CaseFoldPath bool
	RefreshRow   bool
	Connections  func() ([]Connection[Row], error)
	ProcessPath  func(pid uint32) string
	ProcessAppID func(pid uint32) string
	ProcessStart func(pid uint32, row *Row) string
	Enable       func(row *Row) bool
	Read         func(row *Row) (down, up uint64, ok bool)
}

type trackedConnection[Row any] struct {
	entry    Entry
	row      Row
	measured bool
}

type Watcher[Row any] struct {
	engine  string
	system  System[Row]
	tick    int
	tracked map[string]*trackedConnection[Row]
}

func NewWatcher[Row any](engine string, system System[Row]) *Watcher[Row] {
	return &Watcher[Row]{engine: engine, system: system, tracked: map[string]*trackedConnection[Row]{}}
}

func (w *Watcher[Row]) Sample() Line {
	if w.tick%RescanEvery == 0 {
		w.rescan()
	}
	w.tick++
	line := Line{Estats: w.system.Estats, Outside: make([]Entry, 0, len(w.tracked))}
	ids := make([]string, 0, len(w.tracked))
	for id := range w.tracked {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		tracked := w.tracked[id]
		entry := tracked.entry
		if tracked.measured && w.system.Read != nil {
			if down, up, ok := w.system.Read(&tracked.row); ok {
				entry.Down, entry.Up = &down, &up
			}
		}
		line.Outside = append(line.Outside, entry)
	}
	return line
}

func (w *Watcher[Row]) rescan() {
	connections, err := w.system.Connections()
	if err != nil {
		// A failed read doesn't mean the connections closed: keep them.
		fmt.Fprintf(os.Stderr, "can't read the connection table: %v\n", err)
		return
	}
	paths := map[uint32]string{}
	appIDs := map[uint32]string{}
	seen := map[string]bool{}
	for _, c := range connections {
		if !c.Established {
			continue
		}
		local, remote := netip.AddrFrom4(c.Local).String(), netip.AddrFrom4(c.Remote).String()
		if Ignored(local, remote) {
			continue
		}
		path, known := paths[c.PID]
		if !known {
			if w.system.ProcessPath != nil {
				path = w.system.ProcessPath(c.PID)
			}
			paths[c.PID] = path
			if w.system.ProcessAppID != nil {
				appIDs[c.PID] = w.system.ProcessAppID(c.PID)
			}
		}
		if w.sameEngine(path) {
			continue
		}
		id := ConnectionID(local, c.LocalPort, remote, c.RemotePort, c.PID, c.Created)
		seen[id] = true
		if existing := w.tracked[id]; existing != nil {
			if w.system.RefreshRow {
				existing.row = c.Row
			}
			continue
		}
		row := c.Row
		measured := w.system.Estats && (w.system.Enable == nil || w.system.Enable(&row))
		entry := Entry{ID: id, PID: c.PID, Path: path, AppID: appIDs[c.PID], Local: local, Created: c.Created}
		if w.system.ProcessStart != nil {
			entry.ProcessStarted = w.system.ProcessStart(c.PID, &row)
		}
		w.tracked[id] = &trackedConnection[Row]{
			entry:    entry,
			row:      row,
			measured: measured,
		}
	}
	for id := range w.tracked {
		if !seen[id] {
			delete(w.tracked, id)
		}
	}
}

func (w *Watcher[Row]) sameEngine(path string) bool {
	if w.engine == "" || path == "" {
		return false
	}
	if w.system.CaseFoldPath {
		return strings.EqualFold(path, w.engine)
	}
	return path == w.engine
}
