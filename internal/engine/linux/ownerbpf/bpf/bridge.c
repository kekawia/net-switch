/* UNVALIDATED WIP: not compiled, verifier-tested, or part of PR #109. */
/* SPDX-License-Identifier: (MIT OR GPL-2.0-only)
 * Original isolated skb/read provenance experiment; no app identity authority.
 */
#include "abi.h"
#include "provenance.h"
struct atomic64_t { long long counter; } CORE;
struct atomic_t { int counter; } CORE;
struct refcount_struct { struct atomic_t refs; } CORE;
struct sock_common { struct atomic64_t skc_cookie; } CORE;
struct sock { struct sock_common __sk_common; } CORE;
struct ns_common { unsigned int inum; } CORE;
struct net { struct ns_common ns; } CORE;
struct possible_net_t { struct net *net; } CORE;
struct net_device { int ifindex; struct possible_net_t nd_net; } CORE;
struct sk_buff {
    struct sock *sk;
    struct net_device *dev;
    unsigned int len;
    struct refcount_struct users;
} CORE;
struct task_struct { u64 start_boottime; } CORE;
struct raw_args { u64 args[2]; };

struct ns_config {
    u32 abi, enabled;
    u64 epoch;
    u32 ifindex, netns, cpus, readers;
    u64 background_cookie;
    u64 reserved[3];
};
struct ns_health { u64 epoch_faults, init_calls, init_zero, reserved[5]; };
struct ns_cpu {
    u64 serial, depth, captures, guard_miss, cookie_missing, shared, read_fail;
    u64 consumes, frees, perf_consumes, deleted;
    u64 address, seen_serial, cookie, skipped, nested;
};
struct ns_faults {
    u64 epoch;
    u32 cpu, mode;
    u64 serial, address, hits;
    u64 reserved[3];
};
_Static_assert(sizeof(struct ns_config) == 64, "config size");
_Static_assert(sizeof(struct ns_health) == 64, "health size");
_Static_assert(sizeof(struct ns_cpu) == 128, "cpu size");
_Static_assert(sizeof(struct ns_faults) == 64, "fault size");

static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static long (*erase)(void *, const void *) = (void *)3;
static u32 (*cpu_id)(void) = (void *)8;
static u64 (*pid_tgid)(void) = (void *)14;
static void *(*current_task)(void) = (void *)35;
static u64 (*socket_cookie)(void *) = (void *)46;
static long (*read_kernel)(void *, u32, const void *) = (void *)113;
#define READ(dst, src) read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))
#define INLINE static __attribute__((always_inline))
#define MAP(name, kind, count, key_type, value_type, flags) \
    struct { FIELD(type, kind); FIELD(max_entries, count); FIELD(map_flags, flags); \
        TYPE(key, key_type); TYPE(value, value_type); } name SEC(".maps")
MAP(packets, 1, NS_PACKET_SLOTS, u64, struct ns_packet_record, 0);
MAP(readers, 1, NS_READER_LIMIT, struct ns_reader_key, struct ns_reader_registration, 0);
MAP(read_slots, 2, NS_READER_LIMIT, u32, struct ns_reader_slot, 1024);
MAP(config, 2, 1, u32, struct ns_config, 0);
MAP(health, 2, 1, u32, struct ns_health, 1024);
MAP(cpu_state, 6, 1, u32, struct ns_cpu, 0);
#ifdef NS_OWNER_PROOF_FAULTS
MAP(faults, 2, 1, u32, struct ns_faults, 0);
#endif

INLINE void fault(void) {
    u32 zero = 0;
    struct ns_health *h = lookup(&health, &zero);
    if (h) __sync_fetch_and_add(&h->epoch_faults, 1);
}

INLINE int selected(struct net_device *dev, struct ns_config *cfg) {
    u32 index = 0, ns = 0;
    struct net *net = 0;
    return dev && !READ(index, dev->ifindex) && !READ(net, dev->nd_net.net) &&
        net && !READ(ns, net->ns.inum) && index == cfg->ifindex && ns == cfg->netns;
}

INLINE int inject(u32 mode, u64 epoch, u32 cpu, u64 serial, u64 address) {
#ifdef NS_OWNER_PROOF_FAULTS
    u32 zero = 0;
    struct ns_faults *f = lookup(&faults, &zero);
    if (f && f->mode == mode && f->epoch == epoch && f->cpu == cpu &&
        (!f->serial || f->serial == serial) && (!f->address || f->address == address) && !f->hits) {
        __sync_fetch_and_add(&f->hits, 1);
        return 1;
    }
#endif
    return 0;
}

SEC("cgroup_skb/egress") int init_egress_cookie(void *ctx) {
    u32 zero = 0;
    struct ns_health *h = lookup(&health, &zero);
    u64 cookie = socket_cookie(ctx);
    if (h) {
        __sync_fetch_and_add(&h->init_calls, 1);
        if (!cookie) __sync_fetch_and_add(&h->init_zero, 1);
    }
    return 1;
}

SEC("raw_tracepoint/net_dev_start_xmit") int capture(struct raw_args *ctx) {
    u32 zero = 0;
    struct ns_config *cfg = lookup(&config, &zero);
    if (!cfg || cfg->abi != NS_PROVENANCE_ABI || !cfg->enabled || !cfg->epoch) return 0;
    struct net_device *dev = (void *)ctx->args[1];
    if (!selected(dev, cfg)) return 0;
    struct ns_cpu *state = lookup(&cpu_state, &zero);
    if (!state) { fault(); return 0; }
    __sync_fetch_and_add(&state->depth, 1);
    if (*(volatile u64 *)&state->depth != 1) {
        __sync_fetch_and_add(&state->guard_miss, 1);
        goto out;
    }
    if (state->serial == ~0ULL) { fault(); goto out; }
    state->serial++;
    struct sk_buff *skb = (void *)ctx->args[0];
    u64 address = (u64)skb;
    struct ns_packet_record p = { .abi = NS_PROVENANCE_ABI,
        .status = NS_PACKET_CAPTURED, .epoch = cfg->epoch, .ifindex = cfg->ifindex,
        .netns = cfg->netns, .cpu = cpu_id(), .serial = state->serial };
    struct sock *sk = 0;
    /* Fixture-only diagnostics are not consulted by the read decision. */
    state->address = address;
    state->seen_serial = p.serial;
    if (inject(1, p.epoch, p.cpu, p.serial, address)) {
        __sync_fetch_and_add(&state->skipped, 1);
        goto out;
    }
    if (READ(p.length, skb->len) || READ(p.users, skb->users.refs.counter) ||
        READ(sk, skb->sk) || (sk && READ(p.cookie, sk->__sk_common.skc_cookie.counter))) {
        p.status = 0;
        __sync_fetch_and_add(&state->read_fail, 1);
    }
    if (!p.cookie) { p.status = 0; __sync_fetch_and_add(&state->cookie_missing, 1); }
    if (p.users != 1) { p.status = 0; __sync_fetch_and_add(&state->shared, 1); }
    state->cookie = p.cookie;
    if (lookup(&packets, &address)) { fault(); goto out; }
    if (update(&packets, &address, &p, 0)) fault();
    else __sync_fetch_and_add(&state->captures, 1);
out:
    __sync_fetch_and_add(&state->depth, -1);
    return 0;
}

INLINE int terminal(struct sk_buff *skb, u32 kind) {
    u32 zero = 0;
    u64 address = (u64)skb;
    struct ns_config *cfg = lookup(&config, &zero);
    struct ns_cpu *state = lookup(&cpu_state, &zero);
    if (!cfg || !state) return 0;
    struct net_device *dev = 0;
    if (!READ(dev, skb->dev) && selected(dev, cfg)) {
        if (kind == NS_TERMINAL_CONSUME) __sync_fetch_and_add(&state->consumes, 1);
        else __sync_fetch_and_add(&state->frees, 1);
    }
    struct ns_packet_record *found = lookup(&packets, &address);
    if (!found) return 0;
    struct ns_packet_record p = *found;
    /* Retirement is independent of reader matching and publication faults. */
    if (inject(4, p.epoch, p.cpu, p.serial, address)) { p.status = 0; fault(); }
    else if (erase(&packets, &address)) { p.status = 0; fault(); }
    else __sync_fetch_and_add(&state->deleted, 1);
    if (inject(2, p.epoch, p.cpu, p.serial, address)) return 0;
    u64 id = pid_tgid();
    struct ns_reader_key key = { .tgid = id >> 32, .tid = (u32)id };
    struct ns_reader_registration *r = lookup(&readers, &key);
    if (!r || r->slot >= NS_READER_LIMIT || r->epoch != p.epoch ||
        r->ifindex != p.ifindex || r->netns != p.netns || p.epoch != cfg->epoch) return 0;
    u32 slot = r->slot;
    struct ns_reader_slot *s = lookup(&read_slots, &slot);
    if (!s || s->control.abi != NS_PROVENANCE_ABI || s->control.armed != 1 ||
        s->control.registration != r->generation || s->control.epoch != r->epoch ||
        !s->control.sequence) return 0;
    /* Count before stamping: a nested attempt must make the read ambiguous. */
    __sync_fetch_and_add(&s->completion.count, 1);
    if (cfg->background_cookie && p.cookie == cfg->background_cookie)
        __sync_fetch_and_add(&state->nested, 1);
    u64 start = 0;
    struct task_struct *task = current_task();
    if (READ(start, task->start_boottime) || !start) { fault(); return 0; }
    __sync_fetch_and_add(&r->stamp_guard, 1);
    if (*(volatile u64 *)&r->stamp_guard != 1) {
        __sync_fetch_and_add(&r->stamp_guard, -1);
        return 0;
    }
    if (!(r->flags & NS_READER_STAMPED)) {
        r->start_boottime = start;
        r->flags = NS_READER_STAMPED;
    }
    int valid = r->start_boottime == start;
    __sync_fetch_and_add(&r->stamp_guard, -1);
    if (!valid) { fault(); return 0; }
    s->completion.sequence = s->control.sequence;
    s->completion.registration = r->generation;
    s->completion.terminal = kind;
    s->completion.status = p.status;
    s->packet = p;
    return 0;
}
SEC("raw_tracepoint/consume_skb") int consume(struct raw_args *ctx) {
    return terminal((void *)ctx->args[0], NS_TERMINAL_CONSUME);
}
SEC("raw_tracepoint/kfree_skb") int freed(struct raw_args *ctx) {
    return terminal((void *)ctx->args[0], NS_TERMINAL_FREE);
}

/* Fixture-only positive control. trace_entry is 8 bytes on both adapters.
 * The skb pointer field's actual tracefs offset is checked before attachment.
 * No packet map or read-result access: this cannot supply provenance. */
struct consume_event { u64 common; struct sk_buff *skbaddr; };
SEC("tracepoint/skb/consume_skb") int perf_consume(struct consume_event *ctx) {
    u32 zero = 0;
    struct ns_config *cfg = lookup(&config, &zero);
    struct ns_cpu *state = lookup(&cpu_state, &zero);
    struct net_device *dev = 0;
    if (cfg && state && !READ(dev, ctx->skbaddr->dev) && selected(dev, cfg))
        __sync_fetch_and_add(&state->perf_consumes, 1);
    return 0;
}
char ns_bridge_license[] SEC("license") = "Dual MIT/GPL";
