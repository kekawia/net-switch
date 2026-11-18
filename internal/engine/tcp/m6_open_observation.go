package tcp

import "sync"

var m6Opens struct {
	sync.Mutex
	next int
	rows [4096][10]int64
}

func recordM6Open(src, dst uint16, adm, opened, lookup, identity, dial, connected, handshake, done int64) {
	m6Opens.Lock()
	defer m6Opens.Unlock()
	m6Opens.rows[m6Opens.next%len(m6Opens.rows)] = [10]int64{
		int64(m6Opens.next), int64(src), int64(dst), opened - adm, lookup - opened,
		identity - lookup, dial - identity, connected - dial, handshake - connected, done - handshake,
	}
	m6Opens.next++
}

func (f *Forwarder) M6OpenRows() [][10]int64 {
	m6Opens.Lock()
	defer m6Opens.Unlock()
	n := min(m6Opens.next, len(m6Opens.rows))
	rows := make([][10]int64, 0, n)
	for i := m6Opens.next - n; i < m6Opens.next; i++ {
		rows = append(rows, m6Opens.rows[i%len(m6Opens.rows)])
	}
	return rows
}
