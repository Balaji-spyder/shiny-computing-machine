#include <linux/bpf.h>
#include <linux/if_ether.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>  
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Define the port to drop (default to 4040)
#ifndef DROP_PORT
#define DROP_PORT 4040
#endif

SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if it's an IP packet
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    // IP header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // Check if it's a TCP packet
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // TCP header
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // Get destination port 
    __u16 dest_port = bpf_ntohs(tcp->dest);

    // Drop if the destination port matches
    if (dest_port == DROP_PORT) {
        bpf_printk("Dropping TCP packet on port %d\n", DROP_PORT); // For debugging
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
