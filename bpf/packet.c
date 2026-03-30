//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Protocol numbers if not defined
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

struct packet_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  pad1;
    __u16 pad2;
    __u32 len;
    __u32 cpu_id;
    __u16 queue_mapping;
    __u16 pad3;
};

// Single shared ring buffer — 1MB total
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);
} events SEC(".maps");

struct kernel_stats {
    __u64 packets;
    __u64 bytes;
};

// Debug counter: how many packets the XDP hook actually sees
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct kernel_stats);
} packet_count_map SEC(".maps");

SEC("xdp")
int xdp_probe_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // Increment the raw packet and byte counters (always, before any parsing)
    __u32 key = 0;
    struct kernel_stats *stats = bpf_map_lookup_elem(&packet_count_map, &key);
    if (stats) {
        __sync_fetch_and_add(&stats->packets, 1);
        __sync_fetch_and_add(&stats->bytes, (data_end - data));
    }

    // --- Ethernet header ---
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4 for now
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // --- IP header ---
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // ihl is in 32-bit words; minimum is 5 (20 bytes)
    if (ip->ihl < 5)
        return XDP_PASS;

    void *ip_end = (void *)ip + (ip->ihl * 4);
    if (ip_end > data_end)
        return XDP_PASS;

    // Reserve ring buffer space
    struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return XDP_PASS;

    evt->timestamp_ns  = bpf_ktime_get_ns();
    evt->cpu_id        = bpf_get_smp_processor_id();
    evt->queue_mapping = ctx->rx_queue_index;
    evt->len           = bpf_ntohs(ip->tot_len);
    evt->saddr         = ip->saddr;
    evt->daddr         = ip->daddr;
    evt->protocol      = ip->protocol;
    evt->sport         = 0;
    evt->dport         = 0;
    evt->pad1          = 0;
    evt->pad2          = 0;
    evt->pad3          = 0;

    // --- Transport layer (port extraction) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = ip_end;
        if ((void *)(tcp + 1) <= data_end) {
            evt->sport = bpf_ntohs(tcp->source);
            evt->dport = bpf_ntohs(tcp->dest);
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = ip_end;
        if ((void *)(udp + 1) <= data_end) {
            evt->sport = bpf_ntohs(udp->source);
            evt->dport = bpf_ntohs(udp->dest);
        }
    }
    // ICMP and others: sport/dport stay 0 — that's correct

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
