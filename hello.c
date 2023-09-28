#include "packet.h"
#include <linux/ipv6.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
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
if(source==0x0101a8c0){
	bpf_printk("Dropped packet from source:%pI4",&source);
	return XDP_DROP;
}
else{
	unsigned int drop=detect_malicious(ctx);
	if(drop==1){
		bpf_printk("Dropped malicious packet from source:%pI4",&source);
		return XDP_DROP;
         } 
	bpf_printk("Passed packet from source:%pI4",&source);
        return XDP_PASS;
}
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";
