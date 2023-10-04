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
        __type(value, long);
        __uint(max_entries, 768);
} packetmap SEC(".maps");

SEC("xdp")
int hello(struct xdp_md *ctx) {
/* long protocol = lookup_protocol(ctx);
 if (protocol == 1) // ICMP
 {
 bpf_printk("Hello ping\n");
 }
 return XDP_PASS;*/
struct iphdr*iph=retrieve_ip(ctx);
unsigned int source=lookup_source(iph);
__u32 key;
long* value;
if(source==0x0101a8c0){
             key=0;
	bpf_printk("Dropped packet from source:%pI4",&source);
	 value = bpf_map_lookup_elem(&packetmap, &key);
                if (value)
                        *value += 1;
	return XDP_DROP;
}
else{
	unsigned int drop=detect_malicious(ctx);
	if(drop==1){
		key=0;
	 value = bpf_map_lookup_elem(&packetmap, &key);
                if (value)
                        *value += 1;
		bpf_printk("Dropped malicious packet from source:%pI4",&source);
		return XDP_DROP;
         } 
	bpf_printk("Passed packet from source:%pI4",&source);
	key=1;
	 value = bpf_map_lookup_elem(&packetmap, &key);
                if (value)
                        *value += 1;
        return XDP_PASS;
}
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
