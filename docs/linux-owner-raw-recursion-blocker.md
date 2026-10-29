# Modern raw-tracepoint retirement: unresolved design obligation

29 October 2026. Implementation stopped at the source audit, before restoring
the unfinished bridge or dispatching privileged tests. This is a source-backed
design gap, **not an executed TUN reproduction or a measured failure rate**.

## Finding

The attribution design's 5.8 observation is correct: `__bpf_trace_run` does not
use the shared `bpf_prog_active` guard. It does not establish the same terminal
coverage on modern kernels. Modern raw tracepoints have a **per-program,
per-CPU** recursion guard that skips the BPF body when that same program is
already active. This is different from the broad perf/kprobe guard.

Verified primary sources:

- [v5.8, bpf_trace.c:1825](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v5.8#n1825):
  no raw per-program recursion guard in this upstream tag.
- [v5.15, bpf_trace.c:1867](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v5.15#n1867):
  likewise absent in this upstream tag. This does not cover later stable backports.
- [Upstream change 05b24ff9b2cf, 22 September 2022](https://github.com/torvalds/linux/commit/05b24ff9b2cfabfcfd951daaa915a036ab53c9e1):
  adds raw-program recursion prevention after an upstream recursive tracepoint
  report. The commit's reproduction is for `contention_begin`, not TUN.
- [v6.12, bpf_trace.c:2300–2322](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v6.12#n2300)
  and [v6.17, bpf_trace.c:2241–2263](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/trace/bpf_trace.c?h=v6.17#n2241):
  check `this_cpu_inc_return(*(prog->active)) != 1`, increment the kernel
  program-misses counter, and bypass the program body when the check fires.

The kernel guard runs before our device filter, nesting guard, health word,
reader event count and packet-map deletion. Consequently none of those
in-program mechanisms records an invocation the kernel suppressed.

## Why the existing proof is insufficient

The design's retirement argument requires every tracked skb's terminal
callback to run. A missed successful read can be detected in userspace, but a
missed **drop** has no read return to compare. The packet map can retain that
dead skb's address without the missing-read counter or sticky health word
noticing it at that time.

The conditional path requiring proof is:

1. The global raw `kfree_skb` program is active on a CPU, possibly for an
   unrelated device (filtering takes place inside the program).
2. A nested event on that CPU frees a tracked TUN skb. A same-program raw
   invocation is suppressed by the kernel guard.
3. The terminal callback cannot delete that packet record or report the miss.

[v6.17 tun.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/net/tun.c?h=v6.17)
still sends the ring-full path through `kfree_skb_reason`. The source audit
establishes the skipped-callback mechanism and its consequence **if nesting
occurs**; it has not yet reproduced this interleaving for this adapter or
established how frequently it occurs. Nor does this report claim that every
interrupt, every map syscall, or every different BPF program suppresses a raw
tracepoint. The guard is specific to the same program on the same CPU.

Detecting an existing pointer key at a later capture can poison the epoch,
but that is not proof that every dead entry is retired. It also does not
replace the separate capture-miss/reused-address safety obligation. A kernel
program-misses counter is observable later, but the current design explicitly
does not accept delayed miss observation as a repaired per-packet association.

The saved draft's own capture guard cannot count a capture the kernel never
entered. Its terminal code likewise has no solution to skipped retirement.
The draft remains outside the branch and has not been compiled or loaded.

## What must be settled before continuing

The modern adapter needs either a source-and-fixture proof that this
same-program suppression cannot occur on its relevant paths, or a reviewed
change to its retirement/invalidation contract covering it. The existing
perf-counter positive control only demonstrates the other guard; raw beating
perf is not proof that raw observed every required terminal event.

No replacement mechanism, extra polling, new helper requirement, relaxed
positive control, floor increase, or workload exclusion has been chosen.
The original design and locked system design are unchanged. Continue only
after this obligation is resolved in the design; the requested stop-on-design-
error rule takes precedence over completing the bridge by improvisation.

## Checkpoint

Same branch and draft PR 109, rebased onto main
`cf10c6db35b18fadc58830a536d9ec02f6d39fe0`. Only the existing ABI 3 contract
and this finding are published. All sixteen Linux blockers remain unchanged.
P1/P2 runtime proof, modern kernel manifest/lifetime audit, both 5.8 guests,
and identity PR 2 remain outstanding. Earlier CI evidence belongs to the
pre-rebase commit and does not qualify this rebased head.
