package observer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"github.com/kekawia/net-switch/internal/platform/outside"
)

// Connections that go around the routing engine, with their byte counts from
// Windows' per-connection statistics (Get/SetPerTcpConnectionEStats), which
// need administrator rights. This is the PowerShell version's logic, step by
// step: the connection list is read every fifth second, and the counters of
// the connections found are read every second.

type outsideEntry = outside.Entry
type outsideLine = outside.Line

func ignored(local, remote string) bool { return outside.Ignored(local, remote) }

// One row of the connection table.
type TCPConnection struct {
	State      uint32
	Local      [4]byte
	LocalPort  uint16
	Remote     [4]byte
	RemotePort uint16
	PID        uint32
	// A FILETIME: 100 ns steps since 1601-01-01 UTC.
	Created int64
}

// The row Windows' statistics calls take: the PowerShell version built it the
// same way, with the addresses and ports in network byte order.
func (c TCPConnection) NativeRow() mibTcpRow {
	return mibTcpRow{
		State:      TCPStateEstablished,
		LocalAddr:  binary.LittleEndian.Uint32(c.Local[:]),
		LocalPort:  uint32(bits.ReverseBytes16(c.LocalPort)),
		RemoteAddr: binary.LittleEndian.Uint32(c.Remote[:]),
		RemotePort: uint32(bits.ReverseBytes16(c.RemotePort)),
	}
}

// Like .NET's DateTime.ToString("o") for a UTC time, which the PowerShell
// version used: seven fractional digits and a Z.
func FormatCreated(filetime int64) string {
	const ticksPerSecond = 10_000_000
	// Seconds from 1601-01-01 to 1970-01-01.
	const unixEpoch = 11_644_473_600
	t := time.Unix(filetime/ticksPerSecond-unixEpoch, filetime%ticksPerSecond*100).UTC()
	return t.Format("2006-01-02T15:04:05.0000000") + "Z"
}

// The owner and start time are part of the id too, so a reused address and
// port is never mistaken for the old connection.
func connectionID(local string, localPort uint16, remote string, remotePort uint16, pid uint32, created string) string {
	return outside.ConnectionID(local, localPort, remote, remotePort, pid, created)
}

// What the watcher asks Windows. Tests replace it.
type tcpSystem struct {
	estats       bool
	connections  func() ([]TCPConnection, error)
	processPath  func(pid uint32) string
	processStart func(pid uint32) string
	// Returns Windows' result code: 0 means collection is on.
	enable func(row *mibTcpRow) uint32
	read   func(row *mibTcpRow) (down, up uint64, ok bool)
}

type outsideWatcher struct {
	*outside.Watcher[mibTcpRow]
}

func newOutsideWatcher(engine string, system tcpSystem) *outsideWatcher {
	var start func(uint32, *mibTcpRow) string
	if system.processStart != nil {
		start = func(pid uint32, _ *mibTcpRow) string { return system.processStart(pid) }
	}
	return &outsideWatcher{
		Watcher: outside.NewWatcher(engine, outside.System[mibTcpRow]{
			Estats:       system.estats,
			CaseFoldPath: true,
			Connections: func() ([]outside.Connection[mibTcpRow], error) {
				rows, err := system.connections()
				if err != nil {
					return nil, err
				}
				out := make([]outside.Connection[mibTcpRow], len(rows))
				for i, c := range rows {
					out[i] = outside.Connection[mibTcpRow]{
						Established: c.State == TCPStateEstablished,
						Local:       c.Local,
						LocalPort:   c.LocalPort,
						Remote:      c.Remote,
						RemotePort:  c.RemotePort,
						PID:         c.PID,
						Created:     FormatCreated(c.Created),
						Row:         c.NativeRow(),
					}
				}
				return out, nil
			},
			ProcessPath:  system.processPath,
			ProcessStart: start,
			Enable:       func(row *mibTcpRow) bool { return system.enable(row) == 0 },
			Read:         system.read,
		}),
	}
}

func (w *outsideWatcher) sample() outsideLine { return w.Sample() }

const (
	afInet = 2
	// Connected rows only, with the owning process and creation time.
	tcpTableOwnerModuleConnections = 7
	TCPStateEstablished            = 5
	tcpConnectionEstatsData        = 1
)

// MIB_TCPROW.
type mibTcpRow struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
}

// TCP_ESTATS_DATA_RW_v0.
type tcpEstatsDataRw struct {
	EnableCollection byte
}

// TCP_ESTATS_DATA_ROD_v0.
type tcpEstatsDataRod struct {
	DataBytesOut      uint64
	DataSegsOut       uint64
	DataBytesIn       uint64
	DataSegsIn        uint64
	SegsOut           uint64
	SegsIn            uint64
	SoftErrors        uint32
	SoftErrorReason   uint32
	SndUna            uint32
	SndNxt            uint32
	SndMax            uint32
	ThruBytesAcked    uint64
	RcvNxt            uint32
	ThruBytesReceived uint64
}

// MIB_TCPROW_OWNER_MODULE. The table is read byte by byte at these offsets
// (see parseTcpTable); the struct is here so the tests can check them.
type mibTcpRowOwnerModule struct {
	State            uint32
	LocalAddr        uint32
	LocalPort        uint32
	RemoteAddr       uint32
	RemotePort       uint32
	OwningPid        uint32
	CreateTimestamp  int64
	OwningModuleInfo [16]uint64
}

const (
	// MIB_TCPTABLE_OWNER_MODULE: the row count, then padding that puts the
	// rows on an 8-byte boundary.
	tcpTableHeaderSize = 8
	tcpTableRowSize    = 160
)

// Reads a MIB_TCPTABLE_OWNER_MODULE. Addresses are stored as their four bytes
// in order; ports in network byte order in the low 16 bits (Windows says the
// upper 16 bits may hold anything).
func parseTcpTable(table []byte) ([]TCPConnection, error) {
	if len(table) < tcpTableHeaderSize {
		return nil, errors.New("the connection table is cut short")
	}
	count := binary.LittleEndian.Uint32(table)
	if uint64(count) > uint64(len(table)-tcpTableHeaderSize)/tcpTableRowSize {
		return nil, fmt.Errorf("the connection table says %d rows but holds %d bytes", count, len(table))
	}
	connections := make([]TCPConnection, count)
	for i := range connections {
		row := table[tcpTableHeaderSize+i*tcpTableRowSize:]
		connections[i] = TCPConnection{
			State:      binary.LittleEndian.Uint32(row[0:]),
			Local:      [4]byte(row[4:8]),
			LocalPort:  binary.BigEndian.Uint16(row[8:]),
			Remote:     [4]byte(row[12:16]),
			RemotePort: binary.BigEndian.Uint16(row[16:]),
			PID:        binary.LittleEndian.Uint32(row[20:]),
			Created:    int64(binary.LittleEndian.Uint64(row[24:])),
		}
	}
	return connections, nil
}
