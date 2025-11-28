#ifndef __COMMON_H__
#define __COMMON_H__

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define PROBE_NIC_RX            1
#define PROBE_IP_RCV            2
#define PROBE_IP_RCV_FINISH     3
#define PROBE_TCP_V4_RCV        4
#define PROBE_UDP_RCV           5

// Event sent to userspace
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

#endif