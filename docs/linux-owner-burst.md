# Whole-burst recursion validation

Snapshot of the 29 October amendment to the attribution design. Independent
design review and the full hosted proofs remain required before merge.

### Modern retirement rule: validate every burst before release (29 October)

Adopted for implementation after the revised counter proposal and source audit;
independent review and hosted P2 proof remain required before merge. The earlier
first-new-flow-only proposal is superseded. This covers **all raw packets**, not
only TCP SYNs or the first UDP datagram. It does not qualify complete identity.

The original upstream v5.8 through v6.0 raw dispatcher lacks the per-program
recursion guard; v6.1 introduces it with 05b24ff9b2cf (author date 16 September
2022, commit date 22 September). The checked guarded dispatchers call
`bpf_prog_inc_misses_counter` before returning from a suppressed invocation.
`bpf_prog_info.recursion_misses` exists from v5.12. Query each program FD with
`BPF_OBJ_GET_INFO_BY_FD`, checking the returned info length, program identity,
and errors. A present zero is not an absent field. Counter wrap, decrease,
replacement, unavailable field or query error on an unaudited profile refuses
attribution and requests quiescence; never silently treat it as zero.

The only initially named no-counter profiles are **original upstream v5.8
amd64 and arm64**, with the committed floor source/config/object hashes and
guest identity verified before enabling capture. These profiles are not yet
runtime-qualified. No arbitrary 5.x uname or vendor/backported kernel is an
exemption. If the field exists, use the check even on a no-guard upstream tag.
Other absent-field profiles select labelled unknown/degraded attribution until
their exact sources/configuration are audited. No app owner is invented.

Each locked reader retains a private three-counter baseline for its registration
and epoch, obtained **before its first read**. Initialize registrations while
capture is quiesced. Never share or advance another reader's baseline. Read a
burst of at most **32 raw packets**, stopping immediately at EAGAIN, an error,
or a result requesting rebuild; never wait for a burst to fill. This is an
initial experiment bound, not a measured optimum. Preserve copied slot evidence
per read and raw bytes per packet. `count=0`, sole free, multiple terminals,
unstamped/mismatched registration and unhealthy epochs remain refused by ABI 3.
A suppressed own terminal may leave zero completion; neither this nor any
other incomplete slot becomes known. A foreign nested free/count>1 is refused.

After disarming and copying the last result, execute an explicit **full hardware
and compiler memory barrier** before sampling the three program counters
(capture, consume, free: **three get-info calls per burst**). No packet may reach
normalization consumers, admission, forwarding, or a policy decision before
this gate. Normalized UDP segments inherit the certified raw packet's evidence;
no segment of an uncertified burst may escape. Preserve every existing per-read
health check and also sample health at the burst gate. The newer preemptible
raw dispatch path needs no promise that the reader's own callback always runs.

If any counter differs from that reader's baseline, invalidate **every packet**
in the burst, count one `attribution_unknown_recursion` burst event and its
affected raw-packet/datagram counts, and request a full quiesced epoch rebuild.
Missing completion remains separately counted once per successful raw read;
overlapping reason counters do not multiply the total unknown denominator.
Stop all readers/admission, invalidate all uncommitted old-epoch batches and
envelopes, dispose queued old packets, close all collection-owned objects and
reload before any new burst is accepted. Never reset a live map or clear a
poisoned epoch. The publication/epoch fence is shared across readers; counter
baselines are not. Recheck epoch at publication, serialized with epoch stop.
An unchanged post-burst sample advances only that reader's baseline. Idle
periods need no sampling: the next burst checks before releasing any packet.

**Ordering proof and correction to the proposed ring-lock argument:**
[ptr_ring.h](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/ptr_ring.h?h=v6.12)
has different producer and consumer locks. Publication uses `smp_wmb` before
`WRITE_ONCE(queue, skb)`; consumption uses `READ_ONCE` and dependent skb access,
not a shared-lock handoff. That dependency alone does not order a later load
of unrelated program counters. The explicit post-read full barrier closes this
reader-side ordering gap; a second sample without ordering is not a substitute.
The locked pump and its kernel/user transition must retain compiler ordering;
prove the emitted barrier on each architecture, not just the function name.

For stale X at address A to be accepted as Y, Y's capture must also have been
suppressed: if Y's capture runs, the existing-key rule raises sticky health and
invalidates it. Crucially, **Y's own capture-skip increment completes before
Y's transmit callback enqueues Y**, in the same execution path. That write
precedes the producer publication barrier. Y is then observed/dequeued and read;
the explicit reader barrier precedes each counter query. Hence the post-burst
capture-counter sample includes that skip and refuses the whole burst. This
sufficient proof does not rely on an undocumented cross-CPU slab-recycling
barrier from X to Y. Allocator ordering is therefore not a missing prerequisite
to this stale-association proof. X's skipped terminal is still counted and
retirement repaired by reload, but proving that earlier cross-CPU allocator
chain is not needed to detect Y. No counter snapshot needs to be simultaneous:
each completed-before-publication increment must be included in its own sample.
Later concurrent increments may conservatively refuse more traffic.

Source basis: v6.1/v6.12 `__DO_TRACE` disables preemption; stable v7.2.13 instead
uses SRCU-fast and `rcu_read_lock_dont_migrate`, so task preemption can suppress
the reader callback on non-RT as well as RT. Checked `bpf_prog_get_stats` sums
all possible CPUs; 64-bit `u64_stats_sync` does not itself provide the needed
general read barrier. The kernel
[memory-barrier documentation](https://www.kernel.org/doc/html/latest/core-api/wrappers/memory-barriers.html)
distinguishes pointer dependencies from ordering unrelated loads. The branch's
raw-recursion report records source links and the earlier rejected argument.

P2 must prove real recursion-counter growth on 6.1+ and a preempted-reader case
on a suitable preemptible 7.x guest when hosted infrastructure supports it.
Require whole-burst refusal, exactly one reload request, invalidation of other
unpublished reader batches, and no old-epoch publication. Mutation removing the
post-burst check must accept the deliberately retained stale record; a pure
model mutation alone is not kernel proof. Test same- and cross-CPU capture,
multi-reader baselines, query failure/short info length, and batches containing
multiple UDP datagrams. Preserve the separate perf-skip and nested-terminal
positive controls. No retries erase missed preconditions.

Measure N=1/8/32 on hosted native x64 and ARM64 with the same storm workload,
reporting three-call total latency, hold time from first read to batch release,
CPU/throughput, possible CPU count, burst occupancy and refusals. Include the
barrier cost. Do not claim negligible overhead or tune thresholds before data;
99.5%, p95 <10 ms, internal 8 ms headroom and the 10% regression rule stay fixed.
