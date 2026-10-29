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

// Certify is called only after the hardware barrier and all three get-info
// calls. It never clears poison: reload constructs a new guard. Each registered
// reader owns its guard; epoch publication is separately serialized by Bridge.
func (g *BurstGuard) Certify(after [3]CounterSample, sampleErr error) bool {
	if g.poisoned || sampleErr != nil {
		g.poisoned = true
		return false
	}
	for i, c := range after {
		if !c.Present || c.ProgramID != g.previous[i].ProgramID || c.Misses != g.previous[i].Misses {
			g.poisoned = true
			return false
		}
	}
	g.previous = after
	return true
}
