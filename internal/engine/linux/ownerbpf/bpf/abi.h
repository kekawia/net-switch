/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#ifndef NS_OWNER_ABI_H
#define NS_OWNER_ABI_H
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define NS_ABI 1
#define NS_RECORDS 256
#define SEC(s) __attribute__((section(s), used))
#define FIELD(name, value) int (*name)[value]
#define TYPE(name, value) value *name
#define CORE __attribute__((preserve_access_index))

/* Fixed-width, little-endian on the two supported proof architectures.
 * Evidence only: neither an attempt nor an inode is a validated app identity.
 * Start is the group leader's boot-time nanoseconds, NOT /proc ticks. */
struct actor_key {
    u64 cookie;
    u64 start;
    u64 exec;
    u32 tgid;
    u32 reserved;
};
struct actor_evidence {
    u64 inode;
    u64 device;
    u64 observed_ns;
    u32 abi;
    u32 reserved;
};
/* IPv4 fixed header / UDP only in this deliberately bounded proof.
 * Addresses and ports are packet-order bytes. No payload fingerprint. */
struct tuple_key {
    u8 source[4];
    u8 destination[4];
    u8 ports[4];
};
struct tuple_evidence {
    u64 first_cookie;
    u64 conflicts;
};
enum counter { ATTEMPTS, PACKETS, COOKIE_MISSING, READ_FAILURE,
               INSERT_FAILURE, POISON, UNSUPPORTED_PACKET, COUNTERS };
#endif
