package flows

import (
	"math"
	"sync/atomic"
	"time"

	"github.com/kekawia/net-switch/internal/engine/policy"
)

const (
	balanceSampleInterval      = 250 * time.Millisecond
	balanceRateTauSec          = 1.5
	balanceRecentHalfLifeSec   = 2.0
	balanceFaultHalfLifeSec    = 10.0
	balanceDecayTauSec         = 3.0
	balanceSeedBaselineBps     = 1024.0 * 1024.0 // 1 MiB/s prior scale before real traffic measures actual capacity
	balanceMinCapFloorBps      = 16.0 * 1024.0   // 16 KiB/s absolute minimum floor
	balanceProbeFloorRatio     = 0.05            // keep >= 5% probe share on a stalled line so recovery is detected
	balanceActiveRateThreshold = 64.0 * 1024.0   // only decay a loaded line when bulk traffic is actually happening
)

// lineLoad tracks O(1) live traffic and admission pressure for one line.
// Byte counters are updated lock-free from ticket.Add; all other fields are
// owned by Table.mu.
type lineLoad struct {
	totalBytes  atomic.Uint64
	sharedBytes atomic.Uint64

	lastTotal    uint64
	lastShared   uint64
	totalRate    float64
	sharedRate   float64
	effectiveCap float64
	recent       float64
	handshakes   int
	faults       float64
	picks        uint64
	seeded       bool
}

type LineLoadStats struct {
	TotalRate    uint64  `json:"totalRate"`
	SharedRate   uint64  `json:"sharedRate"`
	EffectiveCap uint64  `json:"effectiveCap"`
	Recent       float64 `json:"recent"`
	Handshakes   int     `json:"handshakes"`
	Faults       float64 `json:"faults"`
	Picks        uint64  `json:"picks"`
}

type autoBalancer struct {
	lines      map[string]*lineLoad
	targets    map[string]bool
	lastSample time.Time
	active     bool
}

func newAutoBalancer() *autoBalancer {
	return &autoBalancer{lines: map[string]*lineLoad{}, targets: map[string]bool{}}
}

func (b *autoBalancer) reset() {
	b.lines = map[string]*lineLoad{}
	b.targets = map[string]bool{}
	b.lastSample = time.Time{}
	b.active = false
}

func (b *autoBalancer) lineLocked(id string) *lineLoad {
	if b.lines == nil {
		b.lines = map[string]*lineLoad{}
	}
	l := b.lines[id]
	if l == nil {
		l = &lineLoad{effectiveCap: balanceSeedBaselineBps}
		b.lines[id] = l
	}
	return l
}

// syncPolicy seeds newly eligible AutoBalance lines from Control's share prior
// while retaining already-measured live capacities across policy updates.
func (b *autoBalancer) syncPolicy(p *policy.Policy, now time.Time) {
	if p == nil {
		b.active = false
		b.targets = map[string]bool{}
		return
	}
	for id := range b.lines {
		if !p.HasLine(id) {
			delete(b.lines, id)
		}
	}
	if !p.AutoBalance() {
		b.active = false
		b.targets = map[string]bool{}
		return
	}
	targets := p.ShareTargets()
	if len(targets) == 0 {
		b.active = false
		b.targets = map[string]bool{}
		return
	}
	var totalWeight uint64
	weightByLine := make(map[string]uint64, len(targets))
	activeTargets := make(map[string]bool, len(targets))
	for _, tgt := range targets {
		weightByLine[tgt.Line] += tgt.Weight
		activeTargets[tgt.Line] = true
		totalWeight += tgt.Weight
	}
	b.targets = activeTargets
	// Preserve previously learned capacities when staying in AutoBalance,
	// and seed fresh lines relative to the existing scale (or baseline).
	scale := balanceSeedBaselineBps * float64(len(weightByLine))
	if b.active {
		knownSum, knownWeight := 0.0, uint64(0)
		for line, w := range weightByLine {
			if existing := b.lines[line]; existing != nil && existing.seeded && existing.effectiveCap > 0 {
				knownSum += existing.effectiveCap
				knownWeight += w
			}
		}
		if knownSum > 0 && knownWeight > 0 && totalWeight > 0 {
			scale = knownSum * (float64(totalWeight) / float64(knownWeight))
		}
	}
	for line, w := range weightByLine {
		l := b.lineLocked(line)
		if !l.seeded || !b.active {
			frac := 1.0 / float64(len(weightByLine))
			if totalWeight > 0 {
				frac = float64(w) / float64(totalWeight)
			}
			l.effectiveCap = max(balanceMinCapFloorBps, scale*frac)
			l.lastTotal = l.totalBytes.Load()
			l.lastShared = l.sharedBytes.Load()
			l.seeded = true
		}
	}
	if b.lastSample.IsZero() || !b.active {
		b.lastSample = now
	}
	b.active = true
}

func (b *autoBalancer) sampleLocked(targets []policy.ShareTarget, now time.Time) {
	if b.lastSample.IsZero() {
		b.lastSample = now
		for _, l := range b.lines {
			l.lastTotal = l.totalBytes.Load()
			l.lastShared = l.sharedBytes.Load()
		}
		return
	}
	elapsed := now.Sub(b.lastSample)
	if elapsed < balanceSampleInterval {
		return
	}
	b.lastSample = now
	dt := elapsed.Seconds()
	if dt <= 0 {
		return
	}
	rateAlpha := 1.0 - math.Exp(-dt/balanceRateTauSec)
	recentDecay := math.Pow(0.5, dt/balanceRecentHalfLifeSec)
	faultDecay := math.Pow(0.5, dt/balanceFaultHalfLifeSec)

	for _, l := range b.lines {
		curTotal := l.totalBytes.Load()
		curShared := l.sharedBytes.Load()
		dTotal := uint64(0)
		if curTotal >= l.lastTotal {
			dTotal = curTotal - l.lastTotal
		}
		dShared := uint64(0)
		if curShared >= l.lastShared {
			dShared = curShared - l.lastShared
		}
		l.lastTotal = curTotal
		l.lastShared = curShared

		instTotal := float64(dTotal) / dt
		instShared := float64(dShared) / dt
		l.totalRate = rateAlpha*instTotal + (1.0-rateAlpha)*l.totalRate
		l.sharedRate = rateAlpha*instShared + (1.0-rateAlpha)*l.sharedRate
		l.recent *= recentDecay
		if l.recent < 1e-4 {
			l.recent = 0
		}
		l.faults *= faultDecay
		if l.faults < 1e-4 {
			l.faults = 0
		}
	}

	if len(targets) == 0 {
		return
	}
	maxSharedRate, maxCap := 0.0, 0.0
	seen := make(map[string]bool, len(targets))
	for _, tgt := range targets {
		if seen[tgt.Line] {
			continue
		}
		seen[tgt.Line] = true
		l := b.lineLocked(tgt.Line)
		if l.sharedRate > maxSharedRate {
			maxSharedRate = l.sharedRate
		}
		if l.effectiveCap > maxCap {
			maxCap = l.effectiveCap
		}
	}

	decayAlpha := 1.0 - math.Exp(-dt/balanceDecayTauSec)
	floor := max(balanceMinCapFloorBps, balanceProbeFloorRatio*max(maxSharedRate, maxCap))
	clear(seen)
	for _, tgt := range targets {
		if seen[tgt.Line] {
			continue
		}
		seen[tgt.Line] = true
		l := b.lineLocked(tgt.Line)
		if l.sharedRate > l.effectiveCap {
			// Snap upward immediately when a line proves higher live throughput.
			l.effectiveCap = l.sharedRate
			continue
		}
		// Only decay a line when bulk traffic is active and this line has live
		// shared demand yet delivers below its estimated capacity.
		// Idle lines keep their estimated capacity so they are never starved.
		hasDemand := l.recent >= 0.5 || l.handshakes > 0
		if hasDemand && maxSharedRate >= balanceActiveRateThreshold && l.sharedRate < 0.85*l.effectiveCap {
			target := max(l.sharedRate, floor)
			l.effectiveCap = decayAlpha*target + (1.0-decayAlpha)*l.effectiveCap
		}
	}
}

func (b *autoBalancer) pickLocked(targets []policy.ShareTarget, k uint64, now time.Time) (policy.ShareTarget, bool) {
	if len(targets) == 0 {
		return policy.ShareTarget{}, false
	}
	b.sampleLocked(targets, now)

	// Dedupe candidate targets by resolved physical line (e.g. if one lane failed over onto another).
	unique := make([]policy.ShareTarget, 0, len(targets))
	seen := make(map[string]bool, len(targets))
	for _, tgt := range targets {
		if seen[tgt.Line] {
			continue
		}
		seen[tgt.Line] = true
		unique = append(unique, tgt)
	}
	if len(unique) == 1 {
		return unique[0], true
	}

	start := int(k % uint64(len(unique)))
	// If any healthy line is genuinely idle while another line is already near
	// saturation, prefer the idle line immediately so all lines contribute 100%.
	anySaturated := false
	for _, cand := range unique {
		l := b.lineLocked(cand.Line)
		capBps := max(l.effectiveCap, balanceMinCapFloorBps)
		if l.totalRate/capBps >= 0.85 {
			anySaturated = true
			break
		}
	}
	if anySaturated {
		bestIdle := policy.ShareTarget{}
		bestIdleCap := -1.0
		for i := 0; i < len(unique); i++ {
			cand := unique[(start+i)%len(unique)]
			l := b.lineLocked(cand.Line)
			capBps := max(l.effectiveCap, balanceMinCapFloorBps)
			util := l.totalRate / capBps
			demand := l.recent + float64(l.handshakes)
			if util < 0.25 && demand < 0.5 && l.faults < 0.5 && capBps > bestIdleCap+1e-9 {
				bestIdleCap = capBps
				bestIdle = cand
			}
		}
		if bestIdleCap > 0 {
			return bestIdle, true
		}
	}

	best := unique[start]
	bestGain := -1.0
	for i := 0; i < len(unique); i++ {
		cand := unique[(start+i)%len(unique)]
		l := b.lineLocked(cand.Line)
		capBps := max(l.effectiveCap, balanceMinCapFloorBps)
		util := min(1.0, max(0.0, l.totalRate/capBps))
		demand := l.recent + float64(l.handshakes)
		penalty := 1.0 + 4.0*l.faults
		// Smooth capacity-weighted gain with zero cliff near util=1.0: spreads
		// bursts and active downloads proportionally to each line's live capacity.
		gain := capBps / ((1.0 + demand + 2.0*util) * penalty)
		if gain > bestGain+1e-9 {
			bestGain = gain
			best = cand
		}
	}
	return best, true
}

func (b *autoBalancer) noteAdmitLocked(line string, handshake bool) {
	l := b.lineLocked(line)
	l.recent += 1.0
	l.picks++
	if handshake {
		l.handshakes++
	}
}

func (b *autoBalancer) noteFaultLocked(line string, now time.Time) {
	if line == "" {
		return
	}
	b.sampleLocked(nil, now)
	l := b.lineLocked(line)
	l.faults += 1.0
}

func (b *autoBalancer) statsLocked() map[string]LineLoadStats {
	if !b.active || len(b.targets) == 0 {
		return nil
	}
	out := make(map[string]LineLoadStats, len(b.targets))
	for id := range b.targets {
		l := b.lines[id]
		if l == nil {
			continue
		}
		out[id] = LineLoadStats{
			TotalRate:    uint64(max(0, l.totalRate)),
			SharedRate:   uint64(max(0, l.sharedRate)),
			EffectiveCap: uint64(max(0, l.effectiveCap)),
			Recent:       math.Round(l.recent*100) / 100,
			Handshakes:   l.handshakes,
			Faults:       math.Round(l.faults*100) / 100,
			Picks:        l.picks,
		}
	}
	return out
}
