# High-Performance XDP Layer-3 Forwarding & FIB Router

This project implements and evaluates an in-kernel Layer 3 packet forwarding router utilizing eBPF/XDP (eXpress Data Path). Network packets are processed directly inside the NIC driver hook, where the Linux Forwarding Information Base (FIB) is queried via `bpf_fib_lookup()` to redirect, mutate (MAC/TTL), and forward packets at 10G line rates with zero `sk_buff` allocations.

---

## 1. Network Topology & Hardware Layout


```

+---------------------+          +------------------------------------+          +---------------------+
|   Jetson Nano/AGX   |          |         Middlebox Server           |          |  Laptop / Upstream  |
|       (Client)      |          |            (xdpserver)             |          |     (NAT Gateway)   |
|                     |          |                                    |          |                     |
|  [eno1]             |<==>| [ens8f0]                  [ens8f1] |<==>| [enp0s31f6]         |
|  10.200.1.3/24      |  Direct  | 10.200.1.1/24        10.200.2.1/24 |  Direct  | 10.200.2.2/24       |
|                     |  10G Link|                                    |  10G Link|   |                 |
+---------------------+          +------------------------------------+          |   v (iptables NAT)  |
| [wlp2s0] (Wi-Fi)    |
| Public Internet     |
+---------------------+

```

### Addressing & Port Map

| Node | Interface | IPv4 Address | MAC Address | Function |
| :--- | :--- | :--- | :--- | :--- |
| **Jetson** | `eno1` | `10.200.1.3/24` | `48:b0:2d:ff:10:d0` | Traffic Generator (Default GW: `10.200.1.1`) |
| **Middlebox (In)** | `ens8f0` | `10.200.1.1/24` | `b4:96:91:a3:76:70` | Ingress from Jetson |
| **Middlebox (Out)**| `ens8f1` | `10.200.2.1/24` | `b4:96:91:a3:76:71` | Egress to Gateway (`10.200.2.2`) |
| **Laptop (Egress)**| `enp0s31f6`| `10.200.2.2/24` | `fc:45:96:aa:a6:54` | Upstream Next-Hop & NAT Router |
| **Laptop (WAN)** | `wlp2s0` | DHCP | Hardware Specific | Internet Access Interface |

---

## 2. Core Architecture & Forwarding Mechanics

* **Control Plane (Linux Kernel Routing Table):** Maintains static routes, default gateways, subnet rules, and the ARP neighbor cache.
* **FIB Query Helper (`bpf_fib_lookup`):** Queries kernel routing decisions from within the XDP execution context without entering the Linux network stack.
* **Data Plane Execution (`bpf_redirect` / `XDP_REDIRECT`):** Directly mutates packet headers (TTL decrement, checksum recomputation, MAC rewriting) and sends frames directly out of the resolved target interface.

---

## 3. Kernel BPF Source (`xdp_prog_kern.c`)

```c
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp_router")
int xdp_router_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct bpf_fib_lookup fib_params = {};
    int rc, action = XDP_PASS;
    __u64 nh_off = sizeof(*eth);

    /* Boundary check for Ethernet header */
    if (data + nh_off > data_end)
        return XDP_DROP;

    /* IPv4 Processing */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = data + nh_off;
        if ((void *)(iph + 1) > data_end)
            return XDP_DROP;

        if (iph->ttl <= 1)
            return XDP_PASS;

        /* Populate FIB parameters */
        fib_params.family      = AF_INET;
        fib_params.ipv4_src    = iph->saddr;
        fib_params.ipv4_dst    = iph->daddr;
        fib_params.tot_len     = bpf_ntohs(iph->tot_len);
        fib_params.l4_protocol = iph->protocol;
        fib_params.sport       = 0;
        fib_params.dport       = 0;
        fib_params.ifindex     = ctx->ingress_ifindex;

        /* Query Kernel FIB (1 = BPF_FIB_LOOKUP_DIRECT) */
        rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 1);

        switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            /* Decrement TTL & incremental checksum update */
            iph->ttl--;
            __u32 check = iph->check + bpf_htons(0x0100);
            iph->check = check + (check >= 0xFFFF);

            /* Rewrite MAC addresses */
            __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
            __builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

            /* Redirect packet directly out of target interface */
            return bpf_redirect(fib_params.ifindex, 0);

        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            return XDP_DROP;

        case BPF_FIB_LKUP_RET_NOT_FWDED:
        case BPF_FIB_LKUP_RET_FWD_DISABLED:
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
        case BPF_FIB_LKUP_RET_NO_NEIGH:
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            /* Fall back to standard kernel network stack */
            return XDP_PASS;
        }
    }
    return action;
}

char _license[] SEC("license") = "GPL";

```

---

## 4. System Setup & Configuration

### Node 1: ThinkPad Laptop (Gateway & NAT Router)

```bash
# 1. Interface IP Assignment
sudo ip addr flush dev enp0s31f6
sudo ip addr add 10.200.2.2/24 dev enp0s31f6
sudo ip link set dev enp0s31f6 up

# 2. Kernel Forwarding & Return Route
sudo sysctl -w net.ipv4.ip_forward=1
sudo ip route replace 10.200.1.0/24 via 10.200.2.1 dev enp0s31f6

# 3. NAT Masquerading via Wi-Fi Interface
sudo iptables -t nat -A POSTROUTING -o wlp2s0 -j MASQUERADE
sudo iptables -A FORWARD -i enp0s31f6 -o wlp2s0 -j ACCEPT
sudo iptables -A FORWARD -i wlp2s0 -o enp0s31f6 -m state --state RELATED,ESTABLISHED -j ACCEPT

```

### Node 2: Jetson (Client / Traffic Generator)

```bash
# 1. Interface IP Assignment & Link Up
sudo ip addr flush dev eno1
sudo ip addr add 10.200.1.3/24 dev eno1
sudo ip link set dev eno1 up

# 2. Default Gateway to Middlebox
sudo ip route replace default via 10.200.1.1 dev eno1

# 3. Static ARP Entry for Middlebox Ingress
sudo ip neigh replace 10.200.1.1 lladdr b4:96:91:a3:76:70 dev eno1 nud permanent

```

### Node 3: Middlebox Server (`xdpserver`)

```bash
# 1. Interface IP Assignments & Links Up
sudo ip addr add 10.200.1.1/24 dev ens8f0
sudo ip addr add 10.200.2.1/24 dev ens8f1
sudo ip link set dev ens8f0 up
sudo ip link set dev ens8f1 up

# 2. Default Outbound Route via Laptop
sudo ip route replace default via 10.200.2.2 dev ens8f1

# 3. Disable RP Filter (Prevents BPF_FIB_LKUP_RET_NOT_FWDED)
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.default.rp_filter=0
sudo sysctl -w net.ipv4.conf.ens8f0.rp_filter=0
sudo sysctl -w net.ipv4.conf.ens8f1.rp_filter=0

# 4. Enable IPv4 Forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.forwarding=1

# 5. Lock Permanent Neighbors (Prevents BPF_FIB_LKUP_RET_NO_NEIGH)
sudo ip neigh replace 10.200.1.3 lladdr 48:b0:2d:ff:10:d0 dev ens8f0 nud permanent
sudo ip neigh replace 10.200.2.2 lladdr fc:45:96:aa:a6:54 dev ens8f1 nud permanent

```

---

## 5. Compilation, Attachment & Testing

### 1. Build and Load XDP Program (on Middlebox)

```bash
# Compile
make

# Attach to both 10G interfaces
sudo ip link set dev ens8f0 xdp off
sudo ip link set dev ens8f1 xdp off
sudo ip link set dev ens8f0 xdp obj xdp_prog_kern.o sec xdp_router
sudo ip link set dev ens8f1 xdp obj xdp_prog_kern.o sec xdp_router

```

### 2. Start Live Monitoring (on Middlebox)

```bash
# In Terminal 1: Monitor XDP action counters
sudo ./xdp_stats -d ens8f0

# In Terminal 2 (Optional): Inspect kernel trace prints
sudo cat /sys/kernel/debug/tracing/trace_pipe

```

### 3. Verify Packet Capture (on Laptop)

```bash
# Monitor all Layer-3/Layer-4 packets arriving from Jetson
sudo tcpdump -ni enp0s31f6 host 10.200.1.3

```

### 4. Execute Validation Traffic (from Jetson)

```bash
# Test 1: ICMP Echo Connectivity
ping -c 5 8.8.8.8

# Test 2: Layer 7 HTTP Request
curl -I [http://www.google.com](http://www.google.com)

```

---

## 6. Expected Results & Verification Indicators

* **XDP Driver Action:** The `xdp_stats` utility displays active packet increments under the `XDP_REDIRECT` action with `0 pps` on `XDP_PASS` or `XDP_DROP` during forwarding.
* **Packet Ingress on Laptop:** `tcpdump` confirms delivery of ICMP requests, DNS queries (UDP port 53), and HTTP handshakes (TCP port 80).
* **Application Output:** `curl` returns a valid HTTP status line (`HTTP/1.1 200 OK` or `HTTP/1.1 301 Moved Permanently`).

```

```
