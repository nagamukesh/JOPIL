//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/pkt_sched.h>
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

// TC action codes
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif

struct packet_event {
    __u64 timestamp_ns;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;
    __u8  tcp_flags;
    __u16 pad2;
    __u32 len;
    __u32 cpu_id;
    __u16 queue_mapping;
    __u16 dns_payload_len;  // Length of DNS payload (0 if not DNS)
    __u8  dns_payload[512]; // DNS packet data (only for port 53 UDP)
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
    evt->tcp_flags     = 0;
    evt->sport         = 0;
    evt->dport         = 0;
    evt->pad2          = 0;
    evt->dns_payload_len = 0;

    // --- Transport layer (port extraction + TCP flags) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = ip_end;
        if ((void *)(tcp + 1) <= data_end) {
            evt->sport     = bpf_ntohs(tcp->source);
            evt->dport     = bpf_ntohs(tcp->dest);
            // TCP flags are at offset 13 in the TCP header (after source, dest, seq, ack, data_offset/reserved/flags)
            // Byte at offset 13 contains: [data_offset(4) | reserved(3) | NS(1)] | flags
            // We want the flags byte, which is at tcp offset + 13
            __u8 *flags_byte = (__u8 *)tcp + 13;
            if ((void *)(flags_byte + 1) <= data_end) {
                evt->tcp_flags = *flags_byte;
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = ip_end;
        if ((void *)(udp + 1) <= data_end) {
            evt->sport = bpf_ntohs(udp->source);
            evt->dport = bpf_ntohs(udp->dest);
            
            // Capture DNS payload if dport==53
            if (evt->dport == 53) {
                void *payload_start = (void *)udp + sizeof(*udp);
                void *payload_end = payload_start + 512;
                if (payload_end > data_end) {
                    payload_end = data_end;
                }
                int payload_len = payload_end - payload_start;
                if (payload_len > 0 && payload_len <= 512) {
                    #pragma unroll
                    for (int i = 0; i < 512; i++) {
                        if (payload_start + i < payload_end) {
                            evt->dns_payload[i] = *((__u8 *)(payload_start + i));
                        }
                    }
                    evt->dns_payload_len = payload_len;
                }
            }
        }
    }
    // ICMP and others: sport/dport stay 0 — that's correct

    bpf_ringbuf_submit(evt, 0);
    return XDP_PASS;
}

// TC probe function (for both ingress and egress, capturing full packets)
SEC("tc")
int tc_probe_func(struct __sk_buff *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    
    struct iphdr *ip = NULL;
    
    // Try parsing with ethernet header first (ingress typically has it)
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) <= data_end && bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        ip = (void *)(eth + 1);
    } else {
        // Egress packets (especially locally generated) might not have ethernet header
        // Try parsing IP directly
        ip = (struct iphdr *)data;
    }
    
    // Validate IP header
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    
    // ihl is in 32-bit words; minimum is 5 (20 bytes)
    if (ip->ihl < 5)
        return TC_ACT_OK;
    
    void *ip_end = (void *)ip + (ip->ihl * 4);
    if (ip_end > data_end)
        return TC_ACT_OK;

    // Reserve ring buffer space
    struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt)
        return TC_ACT_OK;

    evt->timestamp_ns  = bpf_ktime_get_ns();
    evt->cpu_id        = bpf_get_smp_processor_id();
    evt->queue_mapping = 0;  // TC doesn't have qmap
    evt->len           = bpf_ntohs(ip->tot_len);
    evt->saddr         = ip->saddr;
    evt->daddr         = ip->daddr;
    evt->protocol      = ip->protocol;
    evt->tcp_flags     = 0;
    evt->sport         = 0;
    evt->dport         = 0;
    evt->pad2          = 0;
    evt->dns_payload_len = 0;

    // --- Transport layer (port extraction + TCP flags + DNS payload) ---
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = ip_end;
        if ((void *)(tcp + 1) <= data_end) {
            evt->sport     = bpf_ntohs(tcp->source);
            evt->dport     = bpf_ntohs(tcp->dest);
            // TCP flags at offset 13
            __u8 *flags_byte = (__u8 *)tcp + 13;
            if ((void *)(flags_byte + 1) <= data_end) {
                evt->tcp_flags = *flags_byte;
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = ip_end;
        if ((void *)(udp + 1) <= data_end) {
            evt->sport = bpf_ntohs(udp->source);
            evt->dport = bpf_ntohs(udp->dest);
            
            // Capture DNS payload if dport==53 or sport==53 (for responses)
            if (evt->dport == 53 || evt->sport == 53) {
                void *payload_start = (void *)udp + sizeof(*udp);
                void *payload_end = payload_start + 512;
                if (payload_end > data_end) {
                    payload_end = data_end;
                }
                int payload_len = payload_end - payload_start;
                if (payload_len > 0 && payload_len <= 512) {
                    #pragma unroll
                    for (int i = 0; i < 512; i++) {
                        if (payload_start + i < payload_end) {
                            evt->dns_payload[i] = *((__u8 *)(payload_start + i));
                        }
                    }
                    evt->dns_payload_len = payload_len;
                }
            }
        }
    }
    // ICMP and others: sport/dport stay 0 — that's correct

    bpf_ringbuf_submit(evt, 0);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
