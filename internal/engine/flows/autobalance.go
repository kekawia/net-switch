package flows

import (
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/kekawia/net-switch/internal/engine/policy"
)

// Auto balancing places each new Shared connection on the line where it adds
// the most speed. A line's capacity is learned from what it carries and is
// lowered only on evidence that its queue is full: new connections take much
// longer than usual to set up on it. Light traffic is never that evidence. A
// line carrying only chat and API calls moves little data because little is
// asked of it, not because it is slow (FatVAP, NSDI 2008, makes the same point
// about idle gaps when estimating a path's bandwidth).
const (
	balanceSampleInterval    = 250 * time.Millisecond
	balanceRateTauSec        = 1.5
	balanceRecentHalfLifeSec = 2.0
	balanceFaultHalfLifeSec  = 10.0
	balanceSeedBaselineBps   = 1024.0 * 1024.0 // per line, before any traffic shows real speeds
	balanceMinCapFloorBps    = 16.0 * 1024.0

	// While a line is congested its estimate follows what it delivers, but never
	// below this fraction of what Control's history says it can do. Once the
	// congestion clears, an estimate below that history drifts back up to it.
	balanceCongestedTauSec         = 3.0
	balancePriorFloorRatio         = 0.5
	balancePriorRecoverHalfLifeSec = 60.0

	// Connection setup delay, measured per destination against its own
	// baseline. A line is congested when the median of its recent setups is at
	// least twice and at least 50 ms over usual: a full queue slows every
	// setup, one slow server slows one.
	balanceSetupWindow         = 7
	balanceSetupMaxAge         = 10 * time.Second
	balanceSetupMinSamples     = 3
	balanceSetupCongestedRatio = 2.0
	balanceSetupCongestedAdded = 50 * time.Millisecond
	balanceSetupBaselineRise   = 0.01 // a slower setup moves the baseline 1% of the way
	balanceSetupBaselineFloor  = time.Millisecond
	balanceSetupBaselineLimit  = 256
	balanceSetupBaselineMaxAge = 10 * time.Minute
)

// lineLoad tracks live traffic, admissions and setup delay for one line.
// totalBytes is updated lock-free from ticket.Add; everything else is owned by
// Table.mu.
type lineLoad struct {
	totalBytes atomic.Uint64

	lastTotal  uint64
	rate       float64 // bytes per second, up plus down, every flow on the line
	cap        float64 // estimated capacity in the same unit
	prior      float64 // capacity Control's history implies, scaled to live estimates
	weight     float64 // this line's fraction of Control's shares
	recent     float64
	handshakes int
	faults     float64
	picks      uint64
	seeded     bool
	setup      setupDelay
}

// setupDelay is the evidence that a line's queue is full. Each successful dial
// is compared with the best recent setup time to the same destination on the
// same line, so a far server is not mistaken for a congested line.
type setupDelay struct {
	recent    [balanceSetupWindow]setupSample // ring of the latest samples
	next      int
	baselines map[netip.Addr]*setupBaseline
}

type setupSample struct {
	at    time.Time
	ratio float64       // took / baseline
	added time.Duration // took - baseline
}

type setupBaseline struct {
	took time.Duration
	seen time.Time
}

type LineLoadStats struct {
	Rate         uint64  `json:"rate"`
	Cap          uint64  `json:"cap"`
	Prior        uint64  `json:"prior"`
	Recent       float64 `json:"recent"`
	Handshakes   int     `json:"handshakes"`
	Faults       float64 `json:"faults"`
	Picks        uint64  `json:"picks"`
	SetupSamples int     `json:"setupSamples"`
	SetupRatio   float64 `json:"setupRatio"`
	SetupAddedMS uint64  `json:"setupAddedMs"`
	Congested    bool    `json:"congested"`
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
		l = &lineLoad{cap: balanceSeedBaselineBps}
		b.lines[id] = l
	}
	return l
}

// syncPolicy records Control's share weights and seeds lines that start
// sharing, keeping what was already learned while Auto balancing stays on.
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
	targets := p.ShareTargets()
	if !p.AutoBalance() || len(targets) == 0 {
		b.active = false
		b.targets = map[string]bool{}
		return
	}
	weights, total := map[string]float64{}, 0.0
	for _, tgt := range targets {
		weights[tgt.Line] += float64(tgt.Weight)
		total += float64(tgt.Weight)
	}
	b.targets = make(map[string]bool, len(weights))
	for line, w := range weights {
		b.targets[line] = true
		l := b.lineLocked(line)
		l.weight = 1 / float64(len(weights))
		if total > 0 {
			l.weight = w / total
		}
	}
	scale := b.scaleLocked()
	if !b.active || scale <= 0 {
		scale = balanceSeedBaselineBps * float64(len(weights))
	}
	for line := range weights {
		l := b.lines[line]
		if !l.seeded || !b.active {
			l.cap = max(balanceMinCapFloorBps, l.weight*scale)
			l.prior = l.cap
			l.lastTotal = l.totalBytes.Load()
			l.seeded = true
		}
	}
	if b.lastSample.IsZero() || !b.active {
		b.lastSample = now
	}
	b.active = true
}

// scaleLocked is the total speed the sharing lines are estimated to have,
// extrapolated from the lines already seeded. A line's prior is its history
// share of that total, so a line that has not carried much yet is assumed to
// be as good, relative to the others, as Control's long-memory peaks say.
func (b *autoBalancer) scaleLocked() float64 {
	sum, weight := 0.0, 0.0
	for line := range b.targets {
		if l := b.lines[line]; l != nil && l.seeded {
			sum += l.cap
			weight += l.weight
		}
	}
	if weight <= 0 {
		return 0
	}
	return sum / weight
}

func (b *autoBalancer) sampleLocked(now time.Time) {
	if b.lastSample.IsZero() {
		b.lastSample = now
		for _, l := range b.lines {
			l.lastTotal = l.totalBytes.Load()
		}
		return
	}
	elapsed := now.Sub(b.lastSample)
	if elapsed < balanceSampleInterval {
		return
	}
	b.lastSample = now
	dt := elapsed.Seconds()
	rateAlpha := 1 - math.Exp(-dt/balanceRateTauSec)
	recentDecay := math.Pow(0.5, dt/balanceRecentHalfLifeSec)
	faultDecay := math.Pow(0.5, dt/balanceFaultHalfLifeSec)
	for _, l := range b.lines {
		cur := l.totalBytes.Load()
		delta := uint64(0)
		if cur >= l.lastTotal {
			delta = cur - l.lastTotal
		}
		l.lastTotal = cur
		l.rate = rateAlpha*(float64(delta)/dt) + (1-rateAlpha)*l.rate
		l.recent *= recentDecay
		if l.recent < 1e-4 {
			l.recent = 0
		}
		l.faults *= faultDecay
		if l.faults < 1e-4 {
			l.faults = 0
		}
	}
	if !b.active {
		return
	}
	scale := b.scaleLocked()
	congestedAlpha := 1 - math.Exp(-dt/balanceCongestedTauSec)
	recoverAlpha := 1 - math.Pow(0.5, dt/balancePriorRecoverHalfLifeSec)
	for line := range b.targets {
		l := b.lines[line]
		if l == nil || !l.seeded {
			continue
		}
		l.prior = l.weight * scale
		floor := max(balanceMinCapFloorBps, balancePriorFloorRatio*l.prior)
		switch {
		case l.rate > l.cap:
			// A line that carries more than estimated has proven it.
			l.cap = l.rate
		case l.setup.congested(now):
			// Its queue is full: what it delivers now is what it can do now.
			l.cap = max(floor, l.cap+congestedAlpha*(l.rate-l.cap))
		case l.cap < l.prior:
			l.cap = min(l.prior, l.cap+recoverAlpha*(l.prior-l.cap))
		}
		l.cap = max(l.cap, floor)
	}
}

// available is the speed a new connection can count on: the estimate, or
// only what the line delivers while its queue is full.
func (l *lineLoad) available(now time.Time) float64 {
	if l.setup.congested(now) {
		return max(l.rate, balanceMinCapFloorBps)
	}
	return max(l.cap, balanceMinCapFloorBps)
}

func (b *autoBalancer) pickLocked(targets []policy.ShareTarget, k uint64, now time.Time) (policy.ShareTarget, bool) {
	if len(targets) == 0 {
		return policy.ShareTarget{}, false
	}
	b.sampleLocked(now)

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
	// If one line is near full while another is genuinely idle, use the idle
	// line: the full one gains nothing from another connection.
	anySaturated := false
	for _, cand := range unique {
		l := b.lineLocked(cand.Line)
		if l.rate/l.available(now) >= 0.85 {
			anySaturated = true
			break
		}
	}
	if anySaturated {
		bestIdle := policy.ShareTarget{}
		bestIdleCap := -1.0
		for i := range unique {
			cand := unique[(start+i)%len(unique)]
			l := b.lineLocked(cand.Line)
			capBps := l.available(now)
			idle := l.rate/capBps < 0.25 && l.recent+float64(l.handshakes) < 0.5 && l.faults < 0.5 && !l.setup.congested(now)
			if idle && capBps > bestIdleCap+1e-9 {
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
	for i := range unique {
		cand := unique[(start+i)%len(unique)]
		l := b.lineLocked(cand.Line)
		capBps := l.available(now)
		util := min(1.0, max(0.0, l.rate/capBps))
		demand := l.recent + float64(l.handshakes)
		penalty := 1.0 + 4.0*l.faults
		// Capacity-weighted with no cliff near util=1: spreads bursts and active
		// downloads in proportion to each line's speed.
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
	b.sampleLocked(now)
	l := b.lineLocked(line)
	l.faults += 1.0
}

// noteSetupLocked records how long a successful dial on a sharing line took.
func (b *autoBalancer) noteSetupLocked(line string, dst netip.Addr, took time.Duration, now time.Time) {
	if !b.active || !b.targets[line] || !dst.IsValid() || took <= 0 {
		return
	}
	b.lineLocked(line).setup.note(dst.Unmap(), took, now)
}

func (s *setupDelay) note(dst netip.Addr, took time.Duration, now time.Time) {
	if s.baselines == nil {
		s.baselines = map[netip.Addr]*setupBaseline{}
	}
	base := s.baselines[dst]
	if base == nil || now.Sub(base.seen) > balanceSetupBaselineMaxAge {
		// The first setup to a destination only tells us its distance.
		if base == nil && len(s.baselines) >= balanceSetupBaselineLimit {
			s.evictOldest()
		}
		s.baselines[dst] = &setupBaseline{took: max(took, balanceSetupBaselineFloor), seen: now}
		return
	}
	reference := base.took
	base.seen = now
	if took < base.took {
		base.took = max(took, balanceSetupBaselineFloor)
	} else {
		base.took += time.Duration(balanceSetupBaselineRise * float64(took-base.took))
	}
	s.recent[s.next] = setupSample{at: now, ratio: max(1.0, float64(took)/float64(reference)), added: max(0, took-reference)}
	s.next = (s.next + 1) % len(s.recent)
}

func (s *setupDelay) evictOldest() {
	var oldest netip.Addr
	var when time.Time
	for addr, base := range s.baselines {
		if when.IsZero() || base.seen.Before(when) {
			oldest, when = addr, base.seen
		}
	}
	delete(s.baselines, oldest)
}

// medians returns how many setups happened in the last ten seconds and the
// median ratio and added time among them. It allocates nothing.
func (s *setupDelay) medians(now time.Time) (count int, ratio float64, added time.Duration) {
	var ratios [balanceSetupWindow]float64
	var adds [balanceSetupWindow]time.Duration
	for _, sample := range s.recent {
		if sample.at.IsZero() || now.Sub(sample.at) > balanceSetupMaxAge {
			continue
		}
		// Insertion keeps both small arrays sorted.
		i := count
		for ; i > 0 && ratios[i-1] > sample.ratio; i-- {
			ratios[i] = ratios[i-1]
		}
		ratios[i] = sample.ratio
		j := count
		for ; j > 0 && adds[j-1] > sample.added; j-- {
			adds[j] = adds[j-1]
		}
		adds[j] = sample.added
		count++
	}
	if count == 0 {
		return 0, 1, 0
	}
	// The lower median: with an even count, half slow is not yet a majority.
	return count, ratios[(count-1)/2], adds[(count-1)/2]
}

// congested reports whether recent setups on this line take at least twice
// their usual time and at least 50 ms longer. Both are needed: a full but
// healthy line adds a few tens of milliseconds, a choked queue adds hundreds.
// Without new setups the evidence ages out in ten seconds, so a line that
// recovered gets tried again.
func (s *setupDelay) congested(now time.Time) bool {
	count, ratio, added := s.medians(now)
	return count >= balanceSetupMinSamples && ratio >= balanceSetupCongestedRatio && added >= balanceSetupCongestedAdded
}

func (b *autoBalancer) statsLocked(now time.Time) map[string]LineLoadStats {
	if !b.active || len(b.targets) == 0 {
		return nil
	}
	out := make(map[string]LineLoadStats, len(b.targets))
	for id := range b.targets {
		l := b.lines[id]
		if l == nil {
			continue
		}
		count, ratio, added := l.setup.medians(now)
		out[id] = LineLoadStats{
			Rate:         uint64(max(0, l.rate)),
			Cap:          uint64(max(0, l.cap)),
			Prior:        uint64(max(0, l.prior)),
			Recent:       math.Round(l.recent*100) / 100,
			Handshakes:   l.handshakes,
			Faults:       math.Round(l.faults*100) / 100,
			Picks:        l.picks,
			SetupSamples: count,
			SetupRatio:   math.Round(ratio*100) / 100,
			SetupAddedMS: uint64(added.Milliseconds()),
			Congested:    l.setup.congested(now),
		}
	}
	return out
}
