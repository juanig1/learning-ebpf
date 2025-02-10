#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/ip.h>

#include <linux/filter.h>

static inline void set_tcp_dport(struct __sk_buff *skb, int nh_off,
                                 __u16 old_port, __u16 new_port)
{
    bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
                        old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, dest),
                        &new_port, sizeof(new_port), 0);
}

static inline void set_tcp_sport(struct __sk_buff *skb, int nh_off,
                                 __u16 old_port, __u16 new_port)
{
    bpf_l4_csum_replace(skb, nh_off + offsetof(struct tcphdr, check),
                        old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, nh_off + offsetof(struct tcphdr, source),
                        &new_port, sizeof(new_port), 0);
}

SEC("tc/ingress")
int tc_ingress_(struct __sk_buff *skb)
{
    struct iphdr ip;
    struct tcphdr tcp;
    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(struct iphdr)))
    {
        bpf_printk("bpf_skb_load_bytes iph failed");
        return TC_ACT_OK;
    }

    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + (ip.ihl << 2), &tcp, sizeof(struct tcphdr)))
    {
        bpf_printk("bpf_skb_load_bytes ethh failed");
        return TC_ACT_OK;
    }

    unsigned int src_port = bpf_ntohs(tcp.source);
    unsigned int dst_port = bpf_ntohs(tcp.dest);

    if (dst_port == 80)
        bpf_printk("INGRESS %pI4:%u -> %pI4:%u", &ip.saddr, src_port, &ip.daddr, dst_port);

    if (dst_port != 80)
        return TC_ACT_OK;

    set_tcp_dport(skb, ETH_HLEN + sizeof(struct iphdr), __constant_htons(80), __constant_htons(8080));

    return TC_ACT_OK;
}

SEC("tc/egress")
int tc_egress_(struct __sk_buff *skb)
{
    struct iphdr ip;
    struct tcphdr tcp;
    unsigned int payload_offset = 0;
	unsigned int payload_length = 0;
    
    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(struct iphdr)))
    {
        bpf_printk("bpf_skb_load_bytes iph failed");
        return TC_ACT_OK;
    }

    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + (ip.ihl << 2), &tcp, sizeof(struct tcphdr)))
    {
        bpf_printk("bpf_skb_load_bytes ethh failed");
        return TC_ACT_OK;
    }

    unsigned int src_port = bpf_ntohs(tcp.source);
    unsigned int dst_port = bpf_ntohs(tcp.dest);
    if (src_port == 80|| dst_port == 80|| src_port == 8080 || dst_port == 8080)
        bpf_printk("EGRESS %pI4:%u -> %pI4:%u", &ip.saddr, src_port, &ip.daddr, dst_port);
    
    //calculate payload offset and length
    ip_header_length = ip.ihl << 2;    //SHL 2 -> *4 multiply
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

    if (0 != bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + (ip.ihl << 2) + sizeof(struct tcphdr), &payload, payload_len)) {
        bpf_printk("PAYLOAD: %d", payload);
    }

    if (src_port != 8080)
        return TC_ACT_OK;

    set_tcp_sport(skb, ETH_HLEN + sizeof(struct iphdr), __constant_htons(8080), __constant_htons(80));

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
