#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>


int counter = 0;

SEC("xdp")
int http(struct xdp_md *ctx) {
    bpf_printk("Hello World %d", counter);
    counter++;
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

        int xdp_program(struct xdp_md *ctx)
    {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
    
        struct ethhdr *eth = data;
    
        struct iphdr *iph = (data + sizeof(struct ethhdr));
        if (iph + 1 > (struct iphdr *)data_end)
        if(iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));
            if (tcph + 1 > (struct tcphdr *)data_end)
            {
                bpf_printk("Invalid TCP header");
                return XDP_DROP;
            }
    
            if (tcph->dest == htons(8000))
            {
                if(GetPayload(ctx, eth, iph, tcph) == 1) {
                     tcp->dest = htons(289);
                }    
                return XDP_PASS;
            }
        }
}