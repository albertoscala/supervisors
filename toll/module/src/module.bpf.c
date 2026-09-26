#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2
#define ETH_P_IP    0x0800

char LICENSE[] SEC("license") = "GPL";

#define MAX_IPS 64
__u32 whitelisted_arrivals[MAX_IPS];
__u32 whitelisted_arrivals_count;
__u32 whitelisted_departures[MAX_IPS];
__u32 whitelisted_departures_count;

static __always_inline int is_whitelisted(__u32* whitelist, __u32 count, __u32 ip)
{
    for (int i = 0; i < MAX_IPS; i++)
    {
        if (i >= count) break;
        if (whitelist[i] == ip) return 1;
    }

    return 0;
}

SEC("tcx/ingress")
int on_arrival(struct __sk_buff* skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)       /* verifier requires this check */
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("IN: %pI4 -> %pI4", &ip->saddr, &ip->daddr);
    
    // Big Endian -> Little Endian
    if (is_whitelisted(whitelisted_arrivals, whitelisted_arrivals_count, bpf_ntohl(ip->saddr)))
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}

SEC("tcx/egress")
int on_departure(struct __sk_buff* skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)       /* verifier requires this check */
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    bpf_printk("OUT: %pI4 -> %pI4", &ip->saddr, &ip->daddr);
    
    // Big Endian -> Little Endian
    if (is_whitelisted(whitelisted_departures, whitelisted_departures_count, bpf_ntohl(ip->daddr)))
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}
