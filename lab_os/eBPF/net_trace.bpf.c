// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

struct event {
    __u32 pid;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
    __u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Хук на входящие пакеты на уровне socket filter
SEC("socket")
int net_monitor(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 0;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 0;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return 0;

    struct event evt = {};
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.saddr = ip->saddr;
    evt.daddr = ip->daddr;
    evt.protocol = ip->protocol;
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        evt.sport = bpf_ntohs(tcp->source);
        evt.dport = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + ip->ihl * 4;
        if ((void *)(udp + 1) > data_end)
            return 0;
        evt.sport = bpf_ntohs(udp->source);
        evt.dport = bpf_ntohs(udp->dest);
    } else {
        evt.sport = 0;
        evt.dport = 0;
    }

    bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
