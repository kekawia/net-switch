/* SPDX-License-Identifier: (MIT OR GPL-2.0-only) */
#ifndef NS_PROVENANCE_H
#define NS_PROVENANCE_H

/* Original ABI 3 declarations. No kernel or libbpf headers are needed. */
#define NS_PROVENANCE_ABI 3
#define NS_PACKET_SLOTS 2048
#define NS_READER_LIMIT 4
#define NS_CPU_LIMIT 512
#define NS_PACKET_CAPTURED 1
#define NS_READER_STAMPED 1
#define NS_TERMINAL_CONSUME 1
#define NS_TERMINAL_FREE 2

typedef unsigned int ns_u32;
typedef unsigned long long ns_u64;

struct ns_packet_record {
    ns_u32 abi, status;
    ns_u64 epoch;
    ns_u32 ifindex, netns;
    ns_u32 cpu, classification;
    ns_u64 serial, cookie;
    ns_u32 length, users;
    ns_u64 owner_version, identity;
    unsigned char reserved[56];
};

struct ns_reader_key { ns_u32 tgid, tid; };
struct ns_reader_registration {
    ns_u32 slot, ifindex, netns, flags;
    ns_u64 generation, epoch, start_boottime, stamp_guard;
};
struct ns_read_control {
    ns_u32 abi, reserved;
    ns_u64 registration, epoch, sequence, armed;
    unsigned char padding[24];
};
struct ns_read_completion {
    ns_u64 count, sequence, registration;
    ns_u32 terminal, status;
    unsigned char padding[32];
};
struct ns_reader_slot {
    struct ns_read_control control;
    struct ns_read_completion completion;
    struct ns_packet_record packet;
};

#define NS_SIZE(type, size) _Static_assert(sizeof(struct type) == size, #type " size")
#define NS_OFFSET(type, member, offset) \
    _Static_assert(__builtin_offsetof(struct type, member) == offset, #type "." #member)
NS_SIZE(ns_packet_record, 128);
NS_OFFSET(ns_packet_record, abi, 0);
NS_OFFSET(ns_packet_record, status, 4);
NS_OFFSET(ns_packet_record, epoch, 8);
NS_OFFSET(ns_packet_record, ifindex, 16);
NS_OFFSET(ns_packet_record, netns, 20);
NS_OFFSET(ns_packet_record, cpu, 24);
NS_OFFSET(ns_packet_record, classification, 28);
NS_OFFSET(ns_packet_record, serial, 32);
NS_OFFSET(ns_packet_record, cookie, 40);
NS_OFFSET(ns_packet_record, length, 48);
NS_OFFSET(ns_packet_record, users, 52);
NS_OFFSET(ns_packet_record, owner_version, 56);
NS_OFFSET(ns_packet_record, identity, 64);
NS_OFFSET(ns_packet_record, reserved, 72);
NS_SIZE(ns_reader_key, 8);
NS_OFFSET(ns_reader_key, tgid, 0);
NS_OFFSET(ns_reader_key, tid, 4);
NS_SIZE(ns_reader_registration, 48);
NS_OFFSET(ns_reader_registration, slot, 0);
NS_OFFSET(ns_reader_registration, ifindex, 4);
NS_OFFSET(ns_reader_registration, netns, 8);
NS_OFFSET(ns_reader_registration, flags, 12);
NS_OFFSET(ns_reader_registration, generation, 16);
NS_OFFSET(ns_reader_registration, epoch, 24);
NS_OFFSET(ns_reader_registration, start_boottime, 32);
NS_OFFSET(ns_reader_registration, stamp_guard, 40);
NS_SIZE(ns_read_control, 64);
NS_OFFSET(ns_read_control, abi, 0);
NS_OFFSET(ns_read_control, reserved, 4);
NS_OFFSET(ns_read_control, registration, 8);
NS_OFFSET(ns_read_control, epoch, 16);
NS_OFFSET(ns_read_control, sequence, 24);
NS_OFFSET(ns_read_control, armed, 32);
NS_OFFSET(ns_read_control, padding, 40);
NS_SIZE(ns_read_completion, 64);
NS_OFFSET(ns_read_completion, count, 0);
NS_OFFSET(ns_read_completion, sequence, 8);
NS_OFFSET(ns_read_completion, registration, 16);
NS_OFFSET(ns_read_completion, terminal, 24);
NS_OFFSET(ns_read_completion, status, 28);
NS_OFFSET(ns_read_completion, padding, 32);
NS_SIZE(ns_reader_slot, 256);
NS_OFFSET(ns_reader_slot, control, 0);
NS_OFFSET(ns_reader_slot, completion, 64);
NS_OFFSET(ns_reader_slot, packet, 128);
#undef NS_SIZE
#undef NS_OFFSET
#endif
