
/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 256);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} tx_port SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,  unsigned char[ETH_ALEN]);
	__type(value, unsigned char[ETH_ALEN]);
	__uint(max_entries, 16);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_params SEC(".maps");

/* Implement packet03/assignment-1 in this section */
static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
	unsigned char tmp[ETH_ALEN];

	/* Swap source and destination Ethernet MAC addresses */
	memcpy(tmp, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ipv6(struct ipv6hdr *ipv6)
{
	struct in6_addr tmp = ipv6->saddr;

	/* Swap source and destination IPv6 addresses */
	ipv6->saddr = ipv6->daddr;
	ipv6->daddr = tmp;
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iphdr)
{
	__be32 tmp = iphdr->saddr;

	/* Swap source and destination IPv4 addresses */
	iphdr->saddr = iphdr->daddr;
	iphdr->daddr = tmp;
}

/* Implement packet03/assignment-1 in this section */
SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply;
	struct icmphdr_common *icmphdr;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header. For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);

	/* --- ASSIGNMENT 1 PATCHING & CHECKSUM LOGIC --- */

	/* 1. Set the new ICMP Type field */
	icmphdr->type = echo_reply;

	/* 2. Recalculate checksum using helper provided in headers */
	/* Since type changed from Echo Request to Echo Reply, adjust the checksum */
	if (eth_type == bpf_htons(ETH_P_IP)) {
		/* Incremental checksum update for IPv4 ICMP: delta is 8 -> 0 (diff = 0x0800) */
		if (icmphdr->cksum >= bpf_htons(0xf7ff)) {
			icmphdr->cksum += bpf_htons(0x0800) + 1;
		} else {
			icmphdr->cksum += bpf_htons(0x0800);
		}
	}else {
		/* IPv6 ICMPv6: type changed from 128 (0x80) -> 129 (0x81).
		 * In network byte order (big-endian), 0x8000 -> 0x8100.
		 * Field increased by 0x0100, so checksum must decrease by 0x0100. */
		if (icmphdr->cksum < bpf_htons(0x0100)) {
			icmphdr->cksum -= bpf_htons(0x0100) + 1;
		} else {
			icmphdr->cksum -= bpf_htons(0x0100);
		}
}

	bpf_printk("echo_reply: %d", echo_reply);

	action = XDP_TX;

out:
	return xdp_stats_record_action(ctx, action);
}

/* Assignment 2 */
SEC("xdp_redirect_map")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	/* unsigned char dst[ETH_ALEN] = {} */	/* Assignment 2: fill in with the MAC address of the left inner interface */
	/* unsigned ifindex = 0; */		/* Assignment 2: fill in with the ifindex of the left interface */

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	/* 1. Parse Ethernet Header & verify verifier bounds (data + sizeof(ethhdr) <= data_end) */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type < 0) {
		action = XDP_ABORTED;
		goto out;
	}

	/* 2. Lookup key 0 in the tx_port DevMap and redirect */
	if (bpf_redirect_map(&tx_port, 0, 0) == XDP_REDIRECT)
		action = XDP_REDIRECT;

out:
	return xdp_stats_record_action(ctx, action);
}


/* Assignment 3: nothing to do here, patch the xdp_prog_user.c program */
SEC("xdp_redirect_map_bi")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct hdr_cursor nh;
        struct ethhdr *eth;
        int eth_type;
        int action = XDP_PASS;
        unsigned char *dst;

        nh.pos = data;

        eth_type = parse_ethhdr(&nh, data_end, &eth);
        if (eth_type == -1)
                goto out;

        /* Look up destination MAC based on incoming frame's source MAC */
        dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
        if (!dst)
                goto out;

        if ((void *)(eth + 1) > data_end)
                goto out;

        /* Rewrite destination MAC */
        memcpy(eth->h_dest, dst, ETH_ALEN);

        /* Redirect using tx_port map (index 0) */
        action = bpf_redirect_map(&tx_port, 0, 0);

out:
        return xdp_stats_record_action(ctx, action);
}

/* Standard BPF IPv4 TTL decrement with incremental checksum update */
static __always_inline int ip_decrease_ttl(struct iphdr *iph)
{
        __u32 check = iph->check;

        check += bpf_htons(0x0100);
        iph->check = (__u16)(check + (check >= 0xFFFF));
        return --iph->ttl;
}

/* Assignment 4: Complete this router program */
SEC("xdp_router")
int xdp_router_func(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct bpf_fib_lookup fib_params = {};
        struct ethhdr *eth = data;
        struct ipv6hdr *ip6h;
        struct iphdr *iph;
        __u16 h_proto;
        __u64 nh_off;
        int rc;
        int action = XDP_PASS;

        nh_off = sizeof(*eth);
        if (data + nh_off > data_end) {
                action = XDP_DROP;
                goto out;
        }

        h_proto = eth->h_proto;
        if (h_proto == bpf_htons(ETH_P_IP)) {
                iph = data + nh_off;

                if ((void *)(iph + 1) > data_end) {
                        action = XDP_DROP;
                        goto out;
                }

                if (iph->ttl <= 1)
                        goto out;

                /* Fill fib_params for IPv4 */
                fib_params.family      = AF_INET;
                fib_params.ipv4_src    = iph->saddr;
                fib_params.ipv4_dst    = iph->daddr;
                fib_params.tot_len     = bpf_ntohs(iph->tot_len);
                fib_params.l4_protocol = iph->protocol;
                fib_params.sport       = 0;
                fib_params.dport       = 0;
		fib_params.ifindex     = ctx->ingress_ifindex;
        } else if (h_proto == bpf_htons(ETH_P_IPV6)) {
                ip6h = data + nh_off;
                if ((void *)(ip6h + 1) > data_end) {
                        action = XDP_DROP;
                        goto out;
                }

                if (ip6h->hop_limit <= 1)
                        goto out;

                /* Fill fib_params for IPv6 */
                struct in6_addr *src = (struct in6_addr *)fib_params.ipv6_src;
                struct in6_addr *dst = (struct in6_addr *)fib_params.ipv6_dst;

                fib_params.family      = AF_INET6;
                *src                   = ip6h->saddr;
                *dst                   = ip6h->daddr;
                fib_params.tot_len     = bpf_ntohs(ip6h->payload_len);
                fib_params.l4_protocol = ip6h->nexthdr;
                fib_params.sport       = 0;
                fib_params.dport       = 0;

        } else {
                goto out;
        }

        fib_params.ifindex = ctx->ingress_ifindex;

        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 1);
	if (iph && iph->saddr == bpf_htonl(0x0a200103)) {
        bpf_printk("JETSON -> DST:%x RC:%d DMAC:%02x:%02x IF:%d\n",
                   bpf_ntohl(fib_params.ipv4_dst), rc,
                   fib_params.dmac[0], fib_params.dmac[1],
                   fib_params.ifindex);
    }
        switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:         /* lookup successful */
                if (h_proto == bpf_htons(ETH_P_IP))
                        ip_decrease_ttl(iph);
                else if (h_proto == bpf_htons(ETH_P_IPV6))
                        ip6h->hop_limit--;

                /* Update destination and source MAC addresses */
                memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
                memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

                /* Redirect to target egress interface */
                action = bpf_redirect(fib_params.ifindex, 0);
                break;

        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
                action = XDP_DROP;
                break;

        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
                /* Pass to kernel network stack */
                action = XDP_PASS;
                break;
        }

out:
        return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
