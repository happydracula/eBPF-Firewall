#include <linux/ipv6.h>
#include <linux/bpf.h>
#include<linux/ip.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <bpf/bpf_helpers.h>
typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;
#define ETH_P_IP        0x0800
#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

#define ETH_P_IP	0x0800		
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)
struct {
        __uint(type, BPF_MAP_TYPE_SOCKMAP);
        __type(key, int);
        __type(value, int);
        __uint(max_entries, 1);
} counter_pass SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_SOCKMAP);
        __type(key, int);
        __type(value, int);
        __uint(max_entries, 1);
} counter_drop SEC(".maps");
static int w[40] = {
     -70,  -91,  -97,  -8,  -20,  -53,   73,   66,    1,   80,
     127,   43,  -85,  29, -103,  -93,   43,  -81,   11,  -30,
      88,   15,   43,  54,  -32,   15,   10,  -21,  -30,   28,
       5,   -8,    9,  35,   61,   75,   -5,   -5,  -69,  -77
};
static int b = -122;
// Returns the protocol byte for an IP packet, 0 for anything else
// static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)
struct iphdr* retrieve_ip(struct xdp_md *ctx){
 void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return NULL;
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {

        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){

    //        bpf_printk("\nSource Addr Parsed:%pI4 \n",&iph->saddr);
            return iph;
        }
    }
    return NULL;
}
unsigned char lookup_protocol(struct iphdr *iph)
{
	if(iph!=NULL){
		return 0;
	}
	else return iph->protocol;
}

unsigned int lookup_source(struct iphdr* iph)
{
    if(iph!=NULL) return iph->saddr;
    return 0;
}
unsigned int detect_malicious(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;

    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end){

             s64 y = b;      
            for (u8 i = 14; i < 34; ++i) //14th byte to 54th byte
    {
        s8 *byte = data + (i); // don't change this
        y += (*byte) * w[i];
    }
	    if(y>0){
		    return 1;
	    }
	    else {
		    return 0;
	    }
        }
    }
    return 0;
}