#include "packet.h"
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, int);
        __uint(max_entries, 1);
} ip_addr_map SEC(".maps");

SEC("xdp")
int hello(struct xdp_md *ctx) {
	
struct iphdr*iph=retrieve_ip(ctx);
__u32 key=0;
unsigned int source=lookup_source(iph);
int* value;
value = bpf_map_lookup_elem(&ip_addr_map, &key);
if (value)   *value =source;
return XDP_PASS;
}
