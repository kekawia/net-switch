package observer

type adapterReading struct {
	Alias string `json:"alias"`
	RX    uint64 `json:"rx"`
	TX    uint64 `json:"tx"`
}

type metersLine struct {
	Adapters []adapterReading `json:"adapters"`
	// At is when the counters were read, in milliseconds on the system-wide
	// monotonic clock (the performance counter), so Control can divide by the
	// time between readings rather than between their arrivals. A busy PC
	// delays readings in the pipe and delivers them back to back, which made
	// one second of traffic look like a fifth of one (2026-11-23).
	At int64 `json:"at,omitempty"`
}
