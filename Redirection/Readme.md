# Packet03: Advanced XDP Redirection & Kernel FIB Router Lab Guide[cite: 3]

## Overview[cite: 3]

This guide provides a unified reference for the entire **Packet03 (Packet Redirection)** module in the XDP tutorial[cite: 3]. It transitions from in-driver packet reflection (`XDP_TX`) to dynamic interface-to-interface redirection using BPF `DEVMAP` and `HASH` maps, culminating in an autonomous Layer-3 router powered by the Linux Kernel Forwarding Information Base (`bpf_fib_lookup`)[cite: 3].

---

## Part 1: Physical Testbed Architecture & Addressing[cite: 3]

```text
      Subnet 1: 192.168.60.0/24                                   Subnet 2: 192.168.70.0/24
+-------------------+                               +-------------------+                               +-------------------+
|      Jetson       |                               |     Middlebox     |                               |  ThinkPad Laptop  |
|     (Node 1)      |                               |    (xdpserver)    |                               |     (Node 2)      |
|  192.168.60.3/24  |                               |                   |                               |  192.168.70.2/24  |
|  GW: 192.168.60.1 |                               |  ens8f0   ens8f1  |                               |  GW: 192.168.70.1 |
|                   |                               |192.168.60.1 192.168.70.1                          |                   |
|     [eth0] <------|-------------------------------|   [XDP]   [XDP]   |-------------------------------|-----> [enp0s31f6] |
| MAC: Jetson_MAC   |                               |                   |                               | MAC:              |
|                   |                               |                   |                               | fc:45:96:aa:a6:54 |
+-------------------+                               +-------------------+                               +-------------------+
```[cite: 3]

### Complete Addressing & Next-Hop Routing Schema[cite: 3]

| Node | Interface | IPv4 Address | Subnet Mask | Default / Next-Hop Gateway |
| :--- | :--- | :--- | :--- | :--- |
| **Jetson (Node 1)** | `eth0` | `192.168.60.3` | `255.255.255.0` (`/24`) | `192.168.60.1` |
| **Middlebox (Port 0)** | `ens8f0` | `192.168.60.1` | `255.255.255.0` (`/24`) | Direct Link / Local |
| **Middlebox (Port 1)** | `ens8f1` | `192.168.70.1` | `255.255.255.0` (`/24`) | Direct Link / Local |
| **Laptop (Node 2)** | `enp0s31f6` | `192.168.70.2` | `255.255.255.0` (`/24`) | `192.168.70.1` |

[cite: 3]

---

## Part 2: Module Progression & Key Differences[cite: 3]

| Feature | Assignment 1 (`xdp_icmp_echo`) | Assignment 2 (`xdp_redirect`) | Assignment 3 (`xdp_redirect_map`) | Assignment 4 (`xdp_router`) |
| :--- | :--- | :--- | :--- | :--- |
| **Forwarding Mechanism** | `XDP_TX` (Ingress reflection) | `bpf_redirect(ifindex, 0)` | `bpf_redirect_map(&tx_port, ...)` | `bpf_fib_lookup()` + `bpf_redirect()` |
| **Directionality** | Ingress interface bounce | Unidirectional | Bidirectional (Dual Port) | Full Bidirectional Routing |
| **MAC Address Handling** | In-place MAC swap | Manual / Static overwrite | BPF Hash map lookup | Dynamically resolved from Kernel ARP FIB |
| **IP Routing & TTL** | In-place IP swap | Untouched | Untouched | Decrements IPv4 TTL & Updates Checksum |
| **Kernel Stack Dependency** | None | None | None | Uses Linux Routing Table & Neighbor Cache |

[cite: 3]

---

## Part 3: Host & Interface Preparation (Pre-requisites)[cite: 3]

Run these setup scripts across the respective nodes before attaching XDP programs[cite: 3].

### 1. Jetson (`eth0`) Host Setup[cite: 3]
```bash
sudo ip addr flush dev eth0
sudo ip addr add 192.168.60.3/24 dev eth0
sudo ip link set dev eth0 up
sudo ip route replace 192.168.70.0/24 via 192.168.60.1 dev eth0
```[cite: 3]

### 2. ThinkPad Laptop (`enp0s31f6`) Host Setup[cite: 3]
```bash
sudo ip addr flush dev enp0s31f6
sudo ip addr add 192.168.70.2/24 dev enp0s31f6
sudo ip link set dev enp0s31f6 up
sudo ip route replace 192.168.60.0/24 via 192.168.70.1 dev enp0s31f6
```[cite: 3]

### 3. Middlebox Base Network Configuration (`xdpserver`)[cite: 3]
```bash
sudo ip addr flush dev ens8f0
sudo ip addr add 192.168.60.1/24 dev ens8f0
sudo ip link set dev ens8f0 up

sudo ip addr flush dev ens8f1
sudo ip addr add 192.168.70.1/24 dev ens8f1
sudo ip link set dev ens8f1 up

sudo ip route replace 192.168.60.0/24 dev ens8f0 proto kernel scope link src 192.168.60.1
sudo ip route replace 192.168.70.0/24 dev ens8f1 proto kernel scope link src 192.168.70.1
```[cite: 3]

---

## Part 4: Assignment 1 — ICMP Echo Responder via `XDP_TX`[cite: 3]

### Objective[cite: 3]
Build an in-driver ICMP echo responder directly at the XDP driver hook[cite: 3]. The program intercepts incoming ICMP Echo Requests (ping), swaps Ethernet MACs and IP addresses, changes ICMP Type from 8 (Request) to 0 (Reply), recalculates the checksum, and returns `XDP_TX` to reflect the frame immediately back out the same interface without hitting the host kernel stack[cite: 3].

### Workflow & Execution Commands[cite: 3]
```bash
# 1. Compile the eBPF kernel program and userspace tools
make

# 2. Attach xdp_icmp_echo to ens8f0 in native driver mode
sudo ip link set dev ens8f0 xdp obj xdp_prog_kern.o sec xdp_icmp_echo

# 3. Clean and prepare BPF filesystem directory for map pinning
sudo rm -rf /sys/fs/bpf/ens8f0 && sudo mkdir -p /sys/fs/bpf/ens8f0

# 4. Pin the xdp_stats_map to make metrics accessible to userspace
sudo bpftool map pin id $(sudo bpftool map list | grep xdp_stats_map | head -n 1 | awk '{print $1}' | tr -d ':') /sys/fs/bpf/ens8f0/xdp_stats_map

# 5. Monitor real-time packet processing statistics on ens8f0
sudo ./xdp_stats -d ens8f0
```[cite: 3]

### Verification & Testing[cite: 3]
```bash
# On Jetson: Send ping requests to the middlebox gateway IP
ping -c 5 192.168.60.1
```[cite: 3]
* **Expected Result:** Instant ICMP Echo Replies return to the Jetson; `xdp_stats` on the middlebox increments the `XDP_TX` counter column[cite: 3].

### Teardown[cite: 3]
```bash
# Detach the XDP program from ens8f0
sudo ip link set dev ens8f0 xdp off

# Unpin and clean up the stats map
sudo rm -rf /sys/fs/bpf/ens8f0
```[cite: 3]

---

## Part 5: Assignment 2 — Static Interface Redirection (`xdp_redirect`)[cite: 3]

### Objective[cite: 3]
Redirect incoming frames from an ingress physical port (`ens8f0`) directly out of an egress physical port (`ens8f1`) using `bpf_redirect(ifindex, 0)`[cite: 3]. The program updates the Ethernet destination MAC to the next hop and forwards raw frames without traversing kernel IP routing stacks[cite: 3].

### Workflow & Execution Commands[cite: 3]
```bash
# 1. Compile source code
make

# 2. Attach the static redirect program to the ingress interface ens8f0
sudo ip link set dev ens8f0 xdp obj xdp_prog_kern.o sec xdp_redirect

# 3. Clean and create BPF pin directory
sudo rm -rf /sys/fs/bpf/ens8f0 && sudo mkdir -p /sys/fs/bpf/ens8f0

# 4. Pin the stats map
sudo bpftool map pin id $(sudo bpftool map list | grep xdp_stats_map | head -n 1 | awk '{print $1}' | tr -d ':') /sys/fs/bpf/ens8f0/xdp_stats_map

# 5. Run the stats monitor
sudo ./xdp_stats -d ens8f0
```[cite: 3]

### Verification & Testing[cite: 3]
```bash
# In Terminal 1 (Laptop): Sniff raw redirected frames arriving on enp0s31f6
sudo tcpdump -ni enp0s31f6 -e

# In Terminal 2 (Jetson): Transmit frames into ens8f0
ping -c 5 192.168.60.1
```[cite: 3]
* **Expected Result:** `tcpdump` on the laptop captures incoming frames forwarded across the middlebox; `xdp_stats` on `ens8f0` increments under `XDP_REDIRECT`[cite: 3].

### Teardown[cite: 3]
```bash
# Detach XDP program from ens8f0
sudo ip link set dev ens8f0 xdp off

# Clean pinned map directory
sudo rm -rf /sys/fs/bpf/ens8f0
```[cite: 3]

---

## Part 6: Assignment 3 — Dynamic Multi-Port Redirection (`xdp_redirect_map`)[cite: 3]

### Objective[cite: 3]
Eliminate hardcoded interface indices and static MAC addresses by using BPF maps (`BPF_MAP_TYPE_DEVMAP` named `tx_port` and `BPF_MAP_TYPE_HASH` named `redirect_params`)[cite: 3]. The user-space loader configures dynamic port-forwarding tables across multiple interfaces, allowing full bidirectional packet transmission[cite: 3].

### Workflow & Execution Commands[cite: 3]
```bash
# 1. Compile source code
make

# 2. Attach program to ens8f0 and configure DEVMAP forwarding toward ens8f1
sudo ./xdp_loader -d ens8f0 --filename xdp_prog_kern.o --progsec xdp_redirect_map

# 3. Attach program to ens8f1 and configure DEVMAP forwarding toward ens8f0
sudo ./xdp_loader -d ens8f1 --filename xdp_prog_kern.o --progsec xdp_redirect_map

# 4. Inspect the kernel DEVMAP forwarding table
sudo bpftool map dump name tx_port

# 5. Open Terminal 1: Monitor ingress stats on ens8f0
sudo ./xdp_stats -d ens8f0

# 6. Open Terminal 2: Monitor ingress stats on ens8f1
sudo ./xdp_stats -d ens8f1
```[cite: 3]

### Verification & Testing[cite: 3]
```bash
# From Jetson: Ping the Laptop
ping -c 5 192.168.70.2

# From Laptop: Ping the Jetson
ping -c 5 192.168.60.3
```[cite: 3]
* **Expected Result:** Packets flow bidirectionally between Jetson and Laptop with zero packet loss; both `xdp_stats` monitors increment `XDP_REDIRECT`[cite: 3].

### Teardown[cite: 3]
```bash
# Detach programs and release DEVMAPs from both interfaces
sudo ./xdp_loader -d ens8f0 -U
sudo ./xdp_loader -d ens8f1 -U
```[cite: 3]

---

## Part 7: Assignment 4 — Full Layer-3 Router via `bpf_fib_lookup` (`xdp_router`)[cite: 3]

### Objective[cite: 3]
Construct an autonomous, kernel-integrated Layer-3 Router directly at the XDP driver level[cite: 3]:
1. Parse Layer-3 IPv4 headers[cite: 3].
2. Query the Linux Forwarding Information Base (FIB) and Neighbor/ARP cache via `bpf_fib_lookup()`[cite: 3].
3. When `bpf_fib_lookup()` returns `BPF_FIB_LKUP_RET_SUCCESS` (0)[cite: 3]:
   - Decrement the IPv4 `ttl` field and update the IP header checksum with `ip_decrease_ttl()`[cite: 3].
   - Overwrite destination MAC (`eth->h_dest`) with the next-hop MAC (`fib_params.dmac`)[cite: 3].
   - Overwrite source MAC (`eth->h_source`) with the egress interface MAC (`fib_params.smac`)[cite: 3].
   - Forward the packet out of the resolved egress port (`fib_params.ifindex`) using `bpf_redirect()`[cite: 3].
4. Fall back to `XDP_PASS` for non-routable traffic or unpopulated neighbor entries so the kernel stack can handle ARP discovery[cite: 3].

### System & Kernel FIB Preparation (Middlebox)[cite: 3]
```bash
# 1. Enable IPv4 packet forwarding globally across the kernel stack
sudo sysctl -w net.ipv4.ip_forward=1

# 2. Enable forwarding across all network interfaces
sudo sysctl -w net.ipv4.conf.all.forwarding=1
sudo sysctl -w net.ipv4.conf.ens8f0.forwarding=1
sudo sysctl -w net.ipv4.conf.ens8f1.forwarding=1

# 3. Disable Reverse Path Filtering to avoid asymmetric routing drops
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo sysctl -w net.ipv4.conf.ens8f0.rp_filter=0
sudo sysctl -w net.ipv4.conf.ens8f1.rp_filter=0

# 4. Prime the ARP neighbor cache from both interfaces
sudo arping -c 2 -I ens8f0 192.168.60.3
sudo arping -c 2 -I ens8f1 192.168.70.2

# 5. Lock static neighbor entries to guarantee instant bpf_fib_lookup hits
sudo ip neigh replace 192.168.70.2 lladdr fc:45:96:aa:a6:54 dev ens8f1 nud permanent
sudo ip neigh replace 192.168.60.3 lladdr 48:b0:2d:ff:10:d0 dev ens8f0 nud permanent
```[cite: 3]

### Router Loading & Execution Steps[cite: 3]
```bash
# 1. Compile kernel router binary
make

# 2. Detach old programs on both interfaces
sudo ip link set dev ens8f0 xdp off
sudo ip link set dev ens8f1 xdp off

# 3. Attach xdp_router to ens8f0
sudo ip link set dev ens8f0 xdp obj xdp_prog_kern.o sec xdp_router

# 4. Attach xdp_router to ens8f1
sudo ip link set dev ens8f1 xdp obj xdp_prog_kern.o sec xdp_router

# 5. Clean and prepare separate pin directories for both interfaces
sudo rm -rf /sys/fs/bpf/ens8f0 /sys/fs/bpf/ens8f1
sudo mkdir -p /sys/fs/bpf/ens8f0 /sys/fs/bpf/ens8f1

# 6. Pin stats map for ens8f0
sudo bpftool map pin id $(sudo bpftool map list | grep xdp_stats_map | head -n 1 | awk '{print $1}' | tr -d ':') /sys/fs/bpf/ens8f0/xdp_stats_map

# 7. Pin stats map for ens8f1
sudo bpftool map pin id $(sudo bpftool map list | grep xdp_stats_map | tail -n 1 | awk '{print $1}' | tr -d ':') /sys/fs/bpf/ens8f1/xdp_stats_map

# 8. Terminal 1: Monitor stats on ens8f0
sudo ./xdp_stats -d ens8f0

# 9. Terminal 2: Monitor stats on ens8f1
sudo ./xdp_stats -d ens8f1
```[cite: 3]

### Verification & Validation[cite: 3]
```bash
# 1. Send ICMP echo requests from Jetson across the router
ping -c 5 192.168.70.2

# 2. Capture traffic on Laptop to verify TTL decrement (ttl=63) and MAC rewrites
sudo tcpdump -ni enp0s31f6 icmp -e

# 3. On Middlebox: View live kernel trace logs from bpf_printk
sudo cat /sys/kernel/debug/tracing/trace_pipe
```[cite: 3]

### Teardown[cite: 3]
```bash
# Detach router programs
sudo ip link set dev ens8f0 xdp off
sudo ip link set dev ens8f1 xdp off

# Remove pinned map directories
sudo rm -rf /sys/fs/bpf/ens8f0 /sys/fs/bpf/ens8f1
```[cite: 3]

---

## Part 8: Troubleshooting & Diagnostics Guide[cite: 3]

| Issue / Symptom | Root Cause | Resolution |
| :--- | :--- | :--- |
| `xdp_stats` shows `XDP_PASS` instead of `XDP_REDIRECT` | `bpf_fib_lookup` returned error code (no route, forwarding off, or empty neighbor cache). | Run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to check `rc` return code. Ensure `net.ipv4.ip_forward=1` and neighbor entries are `REACHABLE` or `PERMANENT`. |
| `bpf_fib_lookup` returns `rc = 5` (`BPF_FIB_LKUP_RET_FWD_DISABLED`) | IP forwarding is disabled on host or ingress interface. | Run `sudo sysctl -w net.ipv4.ip_forward=1` and `sudo sysctl -w net.ipv4.conf.all.forwarding=1`. |
| `bpf_fib_lookup` returns `rc = 6` (`BPF_FIB_LKUP_RET_NO_NEIGH`) | Destination IP is in route table but ARP MAC is missing or `STALE`. | Ping target from middlebox or set static ARP: `sudo ip neigh replace <IP> lladdr <MAC> dev <iface> nud permanent`. |
| ARP packets fail to resolve through router | ARP was intercepted or redirected incorrectly. | Ensure your XDP program passes ARP (`eth->h_proto == bpf_htons(ETH_P_ARP)`) up to the kernel using `return XDP_PASS`. |

[cite: 3]

---

## Part 9: Comprehensive Command Reference[cite: 3]

| Command | Purpose |
| :--- | :--- |
| `sudo sysctl -w net.ipv4.ip_forward=1` | Enables IPv4 forwarding globally so `bpf_fib_lookup()` permits cross-interface routing. |
| `sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=0` | Disables reverse path filtering on an interface to prevent dropping asymmetric traffic. |
| `sudo ip addr add <IP>/<CIDR> dev <iface>` | Assigns a static IPv4 address and subnet prefix to a physical network interface. |
| `sudo ip link set dev <iface> up` | Administratively enables the network link on the specified interface. |
| `sudo ip route replace <Subnet> via <GW> dev <iface>` | Configures a next-hop gateway route for reaching remote subnets. |
| `sudo ip route replace <Subnet> dev <iface> proto kernel scope link src <IP>` | Configures an explicit direct link-scope subnet route on the middlebox. |
| `sudo arping -c <count> -I <iface> <Target_IP>` | Sends directed ARP requests out of a specific interface to populate the neighbor table. |
| `sudo ip neigh replace <IP> lladdr <MAC> dev <iface> nud permanent` | Creates a permanent, non-expiring static ARP entry in the Linux neighbor cache. |
| `sudo ip link set dev <iface> xdp obj <file>.o sec <section>` | Attaches a compiled eBPF/XDP ELF section to an interface in native driver mode. |
| `sudo ip link set dev <iface> xdp off` | Detaches any active XDP program from the specified interface. |
| `sudo bpftool map dump name <map_name>` | Prints all key-value entries currently stored inside a named BPF map. |
| `sudo bpftool map pin id <ID> <path>` | Pins a BPF map to the virtual BPF filesystem so external user programs can read it. |
| `sudo ./xdp_stats -d <iface>` | Runs the user-space monitoring utility to display live XDP action counters per interface. |
| `sudo tcpdump -ni <iface> icmp -e` | Captures ICMP frames while displaying raw Layer 2 Ethernet MAC headers and IP TTL values. |
| `sudo cat /sys/kernel/debug/tracing/trace_pipe` | Streams live kernel debug trace messages generated by `bpf_printk()` inside eBPF code. |

[cite: 3]
