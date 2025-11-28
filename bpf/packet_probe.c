//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct packet_event {
	__u64 timestamp_ns;
	__u32 hash;
	__u32 saddr;
	__u32 daddr;
	__u16 sport;
	__u16 dport;
	__u8  protocol;
	__u8  probe_point;
	__u16 _pad1;
	__u32 len;
	__u32 cpu_id;
	__u16 queue_mapping;
	__u16 _pad2;
};

const volatile struct packet_event *_test = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("xdp")
int xdp_probe_func(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if (data + sizeof(*eth) > data_end)
		return XDP_PASS;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *iph = (struct iphdr *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	__u16 sport = 0, dport = 0;

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
		if ((void *)(tcph + 1) <= data_end) {
			sport = tcph->source;
			dport = tcph->dest;
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)(iph + 1);
		if ((void *)(udph + 1) <= data_end) {
			sport = udph->source;
			dport = udph->dest;
		}
	}

	struct packet_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return XDP_PASS;

	evt->timestamp_ns = bpf_ktime_get_ns();
	evt->saddr = iph->saddr;
	evt->daddr = iph->daddr;
	evt->sport = sport;
	evt->dport = dport;
	evt->protocol = iph->protocol;
	evt->probe_point = 1;
	evt->hash = (iph->saddr ^ iph->daddr ^ iph->protocol);
	evt->len = (unsigned int)(data_end - data);
	evt->cpu_id = bpf_get_smp_processor_id();
	evt->queue_mapping = 0;
	evt->_pad1 = 0;
	evt->_pad2 = 0;

	bpf_ringbuf_submit(evt, 0);
	return XDP_PASS;
}