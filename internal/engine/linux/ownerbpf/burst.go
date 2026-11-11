package ownerbpf

import "errors"

const BurstLimit = 32

// CounterSample contains the identity as well as the monotonic value. A
// missing ABI field is not a zero counter. The initial loader supports only
// counter-bearing profiles; the pinned 5.8 exemption needs its guest manifest.
type CounterSample struct {
	ProgramID uint32
	Present   bool
	Misses    uint64
}

type BurstGuard struct {
	previous [3]CounterSample
	floor58  bool
	poisoned bool
}

func NewBurstGuard(initial [3]CounterSample) (*BurstGuard, error) {
	for i, c := range initial {
		if !c.Present || c.ProgramID == 0 {
			return nil, errors.New("recursion counter unavailable: attribution unsupported")
		}
		for j := 0; j < i; j++ {
			if c.ProgramID == initial[j].ProgramID {
				return nil, errors.New("capture/consume/free require distinct program identities")
			}
		}
	}
	return &BurstGuard{previous: initial}, nil
}

// NewFloor58BurstGuard constructs a guard ONLY for the verified original upstream
// Linux v5.8 floor guest (where bpf_prog_info is 208 bytes ending at run_cnt and
// lacks recursion_misses at offset 208..216, and __bpf_trace_run has no recursion
// guard). If the field is present, or any program ID is missing/duplicated, this
// constructor refuses.
func NewFloor58BurstGuard(initial [3]CounterSample) (*BurstGuard, error) {
	for i, c := range initial {
		if c.Present || c.ProgramID == 0 || c.Misses != 0 {
			return nil, errors.New("invalid sample for v5.8 floor no-counter profile")
		}
		for j := 0; j < i; j++ {
			if c.ProgramID == initial[j].ProgramID {
				return nil, errors.New("capture/consume/free require distinct program identities")
			}
		}
	}
	return &BurstGuard{previous: initial, floor58: true}, nil
}

// ChangedMask returns a 3-bit mask (bit 0 = capture, bit 1 = consume, bit 2 = freed)
// identifying which program counters differ from the guard's last certified baseline.
func (g *BurstGuard) ChangedMask(after [3]CounterSample) uint8 {
	var mask uint8
	for i, c := range after {
		if c.Present != !g.floor58 || c.ProgramID != g.previous[i].ProgramID || c.Misses != g.previous[i].Misses {
			mask |= 1 << i
		}
	}
	return mask
}

// Certify is called only after the hardware barrier and all three get-info
// calls. It never clears poison: reload constructs a new guard. Each registered
// reader owns its guard; epoch publication is separately serialized by Bridge.
func (g *BurstGuard) Certify(after [3]CounterSample, sampleErr error) bool {
	if g.poisoned || sampleErr != nil {
		g.poisoned = true
		return false
	}
	for i, c := range after {
		if c.Present != !g.floor58 || c.ProgramID != g.previous[i].ProgramID || c.Misses != g.previous[i].Misses {
			g.poisoned = true
			return false
		}
	}
	g.previous = after
	return true
}

// CertifySingleReaderConsume certifies a burst for an exclusively owned TUN
// descriptor whose single registered reader already observed a valid armed
// TerminalConsume completion for every read in the burst (and during post-drain
// epoch arming before any armed read runs). Because Linux drivers/net/tun.c
// invokes consume_skb on a TUN TX skb only upon a successful tun_do_read return
// (and uses kfree_skb on queue purge, close, or read error), any consume_skb
// recursion_misses increment while capture (index 0) and freed (index 2)
// remain unchanged and monotonic came from an unrelated skb outside this TUN's
// armed reads. Program identity, presence, error, and monotonicity checks
// remain fail-closed on all three programs.
func (g *BurstGuard) CertifySingleReaderConsume(after [3]CounterSample, sampleErr error) bool {
	if g.poisoned || sampleErr != nil {
		g.poisoned = true
		return false
	}
	for i, c := range after {
		if c.Present != !g.floor58 || c.ProgramID != g.previous[i].ProgramID {
			g.poisoned = true
			return false
		}
		if i == 1 && !g.floor58 {
			if c.Misses < g.previous[i].Misses {
				g.poisoned = true
				return false
			}
			continue
		}
		if c.Misses != g.previous[i].Misses {
			g.poisoned = true
			return false
		}
	}
	g.previous = after
	return true
}
