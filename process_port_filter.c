#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ALLOWED_PORT 4040
#define PROCESS_NAME "myprocess"

SEC("cgroup_skb/egress")
int filter_process_and_port(struct __sk_buff *skb) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Check if this is our target process
    if (__builtin_memcmp(comm, PROCESS_NAME, sizeof(PROCESS_NAME) - 1) == 0) {
        void *data_end = (void *)(long)skb->data_end;
        void *data = (void *)(long)skb->data;

        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > data_end)
            return 1;

        // Only IP packets
        if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
            return 1;

        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end)
            return 1;

        if (ip->protocol != IPPROTO_TCP)
            return 1;

        struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
        if ((void *)(tcp + 1) > data_end)
            return 1;

        __u16 dest_port = bpf_ntohs(tcp->dest);

        // Drop if port is not ALLOWED_PORT
        if (dest_port != ALLOWED_PORT) {
            bpf_printk("Dropping traffic from %s on port %d\n", comm, dest_port);
            return 0; // drop
        }
    }

    return 1; // pass
}

char _license[] SEC("license") = "GPL";

