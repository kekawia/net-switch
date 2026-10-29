/* SPDX-License-Identifier: (MIT OR GPL-2.0-only)
 * Original bounded feasibility probes. These never authorize an owner.
 * Type projections describe fields used by CO-RE, not kernel layout offsets.
 */
#include "abi.h"
struct atomic64_t { long long counter; } CORE;
struct sock_common { struct atomic64_t skc_cookie; } CORE;
struct sock { struct sock_common __sk_common; } CORE;
struct super_block { u32 s_dev; } CORE;
struct inode { unsigned long i_ino; struct super_block *i_sb; } CORE;
struct file { struct inode *f_inode; } CORE;
struct mm_struct { struct file *exe_file; } CORE;
struct task_struct {
    struct task_struct *group_leader;
    u64 start_boottime;
    u64 self_exec_id;
    struct mm_struct *mm;
} CORE;
#if defined(__TARGET_ARCH_x86)
/* Register names are relocated through the running kernel's BTF. */
struct pt_regs { unsigned long di; } CORE;
#define FIRST(ctx) ((ctx)->di)
#elif defined(__TARGET_ARCH_arm64)
struct user_pt_regs { u64 regs[31]; } CORE;
struct pt_regs { struct user_pt_regs user_regs; } CORE;
#define FIRST(ctx) ((ctx)->user_regs.regs[0])
#else
#error Unsupported proof architecture
#endif

static void *(*lookup)(void *, const void *) = (void *)1;
static long (*update)(void *, const void *, const void *, u64) = (void *)2;
static u64 (*ktime)(void) = (void *)5;
static u64 (*pid_tgid)(void) = (void *)14;
static long (*packet_bytes)(void *, u32, void *, u32) = (void *)26;
static u64 (*socket_cookie)(void *) = (void *)46;
static void *(*current_task)(void) = (void *)35;
static u64 (*current_cgroup)(void) = (void *)80;
static long (*read_kernel)(void *, u32, const void *) = (void *)113;
#define READ(dst, src) read_kernel(&(dst), sizeof(dst), __builtin_preserve_access_index(&(src)))

struct { FIELD(type, 1); FIELD(max_entries, NS_RECORDS);
    TYPE(key, struct actor_key); TYPE(value, struct actor_evidence);
} actors SEC(".maps");
struct { FIELD(type, 1); FIELD(max_entries, NS_RECORDS);
    TYPE(key, struct tuple_key); TYPE(value, struct tuple_evidence);
} tuples SEC(".maps");
struct { FIELD(type, 2); FIELD(max_entries, COUNTERS);
    TYPE(key, u32); TYPE(value, u64);
} counters SEC(".maps");
struct { FIELD(type, 2); FIELD(max_entries, 1);
    TYPE(key, u32); TYPE(value, u64);
} scope SEC(".maps");

static __attribute__((always_inline)) void count(u32 id) {
    u64 *n = lookup(&counters, &id);
    if (n) __sync_fetch_and_add(n, 1);
}
static __attribute__((always_inline)) void poison(void) {
    count(INSERT_FAILURE);
    count(POISON); /* Permanent for this collection; no TTL or reset API. */
}

SEC("cgroup/sock_create") int initialize_cookie(void *ctx) {
    /* Creator is intentionally not recorded as the sender. */
    if (!socket_cookie(ctx)) count(COOKIE_MISSING);
    return 1;
}

SEC("kprobe/udp_sendmsg") int observe_send(struct pt_regs *ctx) {
    u32 zero = 0;
    u64 *cgroup = lookup(&scope, &zero);
    if (!cgroup || !*cgroup || *cgroup != current_cgroup()) return 0;
    struct sock *sk = 0;
    struct task_struct *leader = 0, *task = current_task();
    struct mm_struct *mm = 0;
    struct file *exe = 0;
    struct inode *inode = 0;
    struct super_block *sb = 0;
    struct actor_key key = {};
    struct actor_evidence value = { .abi = NS_ABI };
    u32 dev = 0;
    if (READ(sk, FIRST(ctx)) || READ(key.cookie, sk->__sk_common.skc_cookie.counter)) goto unreadable;
    if (!key.cookie) { count(COOKIE_MISSING); return 0; }
    if (READ(leader, task->group_leader) || READ(key.start, leader->start_boottime) ||
        READ(key.exec, leader->self_exec_id) || READ(mm, task->mm) ||
        READ(exe, mm->exe_file) || READ(inode, exe->f_inode) ||
        READ(value.inode, inode->i_ino) || READ(sb, inode->i_sb) || READ(dev, sb->s_dev)) goto unreadable;
    key.tgid = pid_tgid() >> 32;
    value.device = dev;
    value.observed_ns = ktime();
    count(ATTEMPTS);
    long err = update(&actors, &key, &value, 1); /* immutable BPF_NOEXIST */
    if (err && err != -17) poison();
    return 0;
unreadable:
    count(READ_FAILURE);
    return 0;
}

SEC("cgroup_skb/egress") int observe_packet(void *ctx) {
    u8 header[28];
    if (packet_bytes(ctx, 0, header, sizeof(header)) || header[0] != 0x45 ||
        header[9] != 17 || (header[6] & 0x3f) || header[7]) {
        count(UNSUPPORTED_PACKET);
        return 1;
    }
    u64 cookie = socket_cookie(ctx);
    if (!cookie) { count(COOKIE_MISSING); return 1; }
    struct tuple_key key = {};
    __builtin_memcpy(key.source, header + 12, 4);
    __builtin_memcpy(key.destination, header + 16, 4);
    __builtin_memcpy(key.ports, header + 20, 4);
    struct tuple_evidence value = { .first_cookie = cookie };
    count(PACKETS);
    long err = update(&tuples, &key, &value, 1);
    if (err == -17) {
        struct tuple_evidence *old = lookup(&tuples, &key);
        if (!old) poison();
        else if (old->first_cookie != cookie) __sync_fetch_and_add(&old->conflicts, 1);
    } else if (err) poison();
    return 1;
}

char ns_owner_license[] SEC("license") = "Dual MIT/GPL";
