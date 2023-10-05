#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

/* In this example we use libbpf-devel and libxdp-devel */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
static int ifindex;
struct xdp_program *prog = NULL;
static int stat_map_fd;
static void poll_stats()
{
    long dropped,passed;
    int key;
    printf("Packets Dropped\tPackets Passed\t Total Packets Processed\n");
    
	key=0;
        bpf_map_lookup_elem(stat_map_fd, &key, &dropped);
	key=1;
	bpf_map_lookup_elem(stat_map_fd, &key, &passed);
	printf("%ld\t\t\t\t%ld\t\t\t%ld\n",dropped,passed,dropped+passed);
	
    
}
static void int_exit(int sig)
{
    poll_stats();
    xdp_program__close(prog);
    exit(0);
}
int main(int argc, char *argv[])
{
    int prog_fd,w_map_fd, ret;
    struct bpf_object *bpf_obj;

    if (argc != 2) {
        printf("Usage: %s IFNAME\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("get ifindex from interface name failed\n");
        return 1;
    }

    /* load XDP object by libxdp */
    prog = xdp_program__open_file("hello.o", "xdp", NULL);
    if (!prog) {
        printf("Error, load xdp prog failed\n");
        return 1;
    }

    /* attach XDP program to interface with skb mode
     * Please set ulimit if you got an -EPERM error.
     */
     bpf_obj = xdp_program__bpf_obj(prog);
      ret = xdp_program__attach(prog, ifindex, XDP_MODE_SKB, 0);
    if (ret) {
        printf("Error, Set xdp fd on %d failed\n", ifindex);
        return ret;
    }
   stat_map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "packetmap");
    if (stat_map_fd < 0) {
        printf("Error, get map fd from bpf obj failed\n");
    }
    
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
   while(1);
    return 0;
}
