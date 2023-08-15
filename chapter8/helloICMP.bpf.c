#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "packet.h"

SEC("xdp")
int ping(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    unsigned char protocol = 0;
    
    struct ethhdr *eth = data; 
    if (data + sizeof(struct ethhdr) > data_end) 
        return XDP_PASS;
    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) 
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP 
        struct iphdr *iph = data + sizeof(struct ethhdr); 
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;   
        if (protocol == 1){
            // bpf_printk("Hello ping");
            struct icmphdr * icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr); 
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) <= data_end){
                bpf_printk("type: %d", icmp->type);
                if (icmp->type == 0){
                    bpf_printk("Echo Reply");
                }else if (icmp->type == 8){
                    bpf_printk("Echo Request");
                }
            }
        }

    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
