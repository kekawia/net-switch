# Modern raw-tracepoint retirement: unresolved design obligation

**Latest status, 29 October:** the revised *whole-burst* rule is adopted for
implementation with an explicit post-read full barrier and private reader
baselines. See [the burst rule and ordering proof](linux-owner-burst.md).
The earlier rejected first-flow-only argument below is retained as history.
The source-level blocker has a specified resolution; runtime P2 controls,
mutation evidence and storm cost remain unproved. This is not qualification.

29 October 2026. Implementation stopped at the source audit, before restoring
the unfinished bridge or dispatching privileged tests. This is a source-backed
design gap, **not an executed TUN reproduction or a measured failure rate**.

**Proposed counter-check resolution reviewed, 29 October:** the counter ABI
is real, but the proposal is not adopted. Step 1 does not hold on the latest
stable preemptible kernels, and step 3's first-UDP-datagram scope differs from
the retained per-datagram contract. Details below. This does not prove that a
revised counter-check design is impossible.

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

## Verification of the proposed recursion-counter resolution

### Confirmed: introduction and observable counter

The upstream raw-program guard is absent from the original v6.0 source and
present in v6.1. Change 05b24ff9b2cf has author date 16 September 2022 and
committer date 22 September; the earlier date in this report was the commit
date, not the patch's author date. Original upstream 5.8 through 6.0 precedes
this guard. These statements do not classify every downstream backport.

`recursion_misses` is absent from the
[v5.11 UAPI](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h?h=v5.11)
and present in the
[v5.12 UAPI](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/bpf.h?h=v5.12).
In the checked v6.1, v6.12 and v7.2.13 raw dispatchers, the recursion-refusal
branch calls `bpf_prog_inc_misses_counter`. Their program-info path sums the
per-CPU misses and exports the total through `bpf_prog_info.recursion_misses`.
This read does not require enabling runtime-duration statistics.

Field absence must be distinguished from a present counter containing zero.
The returned info length can establish ABI field availability; a downstream
kernel's version string or absent field alone does not prove the absence of
a privately backported guard. Only audited no-guard profiles have that proof.

### Step 1: valid in the checked older dispatchers, false as a general rule

In [v6.1 tracepoint.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/tracepoint.h?h=v6.1)
and [v6.12 tracepoint.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/tracepoint.h?h=v6.12),
`__DO_TRACE` disables preemption around the callback. The synchronous
`tun_chr_read_iter` -> `tun_do_read` -> consume/free path remains in the calling
task. A different task cannot run that callback on the CPU while an outer
non-preemptible invocation is active. Our selected helpers do not recursively
perform a TUN read. Interrupt nesting remains possible in the other direction.

**PREEMPT_RT distinction:** the explicit `preempt_disable_notrace` in those
two upstream versions still increments the preemption count; it is not
converted to migration-only exclusion by RT. I found no RT-specific break
of that particular older tracepoint-call argument. This is not a blanket RT
qualification or an audit of every vendor RT patch set.

For the latest stable examined, **v7.2.13** (kernel.org's stable listing on
29 October), the argument changes even without RT:

- [tracepoint.h:315](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/tracepoint.h?h=v7.2.13#n315)
  wraps ordinary callbacks in SRCU-fast, without the former preemption guard.
- [bpf_trace.c:2116](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/trace/bpf_trace.c?h=v7.2.13#n2116)
  uses `rcu_read_lock_dont_migrate` for the non-sleepable raw program.
- [rcupdate.h:977](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/rcupdate.h?h=v7.2.13#n977)
  disables migration with CONFIG_PREEMPT_RCU, then takes the preemptible RCU
  read lock. Staying on one CPU is not the same as keeping another task off it.
- [bpf.h:2185](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/include/linux/bpf.h?h=v7.2.13#n2185)
  still guards the active program per CPU. ARM64 briefly disables preemption
  to update its context bytes, then re-enables it before the BPF body.

An upstream confirmation independent of this reading is
[cc337974cd10](https://github.com/torvalds/linux/commit/cc337974cd1084f9821179eb66f4e470d9fd2ed8):
it fixes another tracepoint consumer after a46023d5616e removed the implicit
preemption exclusion. SRCU-fast's read-side primitive also contains no
whole-callback preemption disable.

Consequently, task A may be preempted while this raw program remains active;
the reader task B may then run on the same CPU and have its own terminal
invocation refused. This is a source-permitted schedule, not an executed
reproduction. Treating only RT as unsupported/unknown would not cover it:
ordinary preemptible non-RT builds also use this path. No new product exclusion
has been adopted.

### Step 2: useful conditional argument, with a contract correction

For the stated stale-X/reused-address-Y case, if Y's own terminal runs, a
post-read counter sample can observe the completed skipped callbacks in that
history. The nested-skip counter is incremented synchronously before the
skipped invocation returns. This is a useful candidate proof for a checked
read, not proof of the complete proposed protocol on every kernel/config.

The existing design does **not** silently overwrite an unexpected existing
pointer record: it raises sticky health and invalidates the affected result.
A successful capture therefore detects the stale key rather than repairing it
by overwriting it. The proposal must preserve that fault rule.

With a preemptible dispatcher, the reader-terminal premise must be handled
explicitly instead of assumed. A missing completion already refuses evidence,
so disproving step 1 alone does not disprove all possible counter-based fixes.

### Step 3: first-packet-only and one-call claims do not match the contract

The design's reader section explicitly requires an envelope per UDP datagram,
and its conflict section requires current ownership/version validation at
**both forwarding paths**, including already queued datagrams. First admission
is not the only point at which UDP ownership evidence matters. A check scoped
only to a new UDP session does not validate later envelopes or provide the
specified retirement/health observation bound when only established traffic
continues. Changing that scope needs a revised proof, not just an optimization.

Current production code still uses periodic identity reconciliation, with
freshness checks in `internal/engine/udp/nat.go` and `readiness.go`; the future
per-datagram provenance/conflict layer is not implemented there yet. Existing
production behavior must not be cited as evidence that the new contract is met.

[v7.2.13 syscall.c:5616](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/bpf/syscall.c?h=v7.2.13#n5616)
accepts **one FD per get-info syscall**. Checking capture plus a terminal
program takes at least two calls, not one. The saved design has separate
consume and free programs, hence three program counters if all are checked.
[The stats reader at line 2548](https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/kernel/bpf/syscall.c?h=v7.2.13#n2548)
walks all possible CPUs. Cost is unmeasured and depends on that count; no
storm-cost number or harmless-overhead claim is available.

An eventual protocol must also specify per-reader versus shared baselines,
in-flight envelopes during a detected miss, and the quiesced reload barrier.
A shared baseline must not consume a miss on behalf of another reader and
leave that reader's old envelope accepted. The existing one-read sticky-health
bound cannot silently become an unbounded wait for the next new flow.

### Step 4 and disposition

`attribution_unknown_recursion` and never inventing an owner are consistent
with the existing refusal policy, but no such metric or runtime check was
implemented because the prerequisite argument failed verification.

As requested, implementation stops rather than selecting a replacement design.
The authoritative design is not changed to claim this resolution. No positive
control, mutation result, guest boot, or cost measurement is claimed. A revised
proposal must cover preemptible raw dispatch, the actual UDP evidence consumers,
the necessary program-FD queries and quiescence across all readers.
