# Software Networks Project: M14 – Packet TTL Inspection (Netfilter)

**Author:** Marta Rolbiecka [0383386] <br>
**Level:** Kernel Module Development <br>
**Course:** Software Networks (2025-2026)

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Code Architecture & Data Structures](#2-code-architecture--data-structures)
3. [Project Structure](#3-project-structure)
4. [Environment Setup & Troubleshooting](#4-environment-setup--troubleshooting)
5. [Building the Project](#5-building-the-project)
6. [Running the Module](#6-running-the-module)
7. [Testing & Verification](#7-testing--verification)

---

## 1. Project Overview

This project implements a custom Linux Kernel Module (LKM) designed to inspect network traffic at the kernel level. The core objective of the M14 task is to utilize the Linux **Netfilter subsystem** to intercept routing packets (both IPv4 and IPv6) and extract their Time-To-Live (TTL) or Hop Limit values before they are processed by the higher levels of the network stack.

Unlike user-space packet sniffers (like Wireshark/tcpdump) which rely on packet copying via `libpcap`, this implementation operates entirely within kernel space. It hooks directly into the networking stack, ensuring deep inspection with minimal overhead. The project is executed and tested within a custom QEMU micro-VM environment orchestrated by Podman.

---

## 2. Code Architecture & Data Structures

All packet processing logic is encapsulated within a single kernel module (`m14_ttl.c`). Below is a detailed breakdown of the key kernel APIs and structures utilized.

## 2.1 The Netfilter Hook Structure
To intercept packets, the module registers callback functions using the Netfilter framework. Because we are inspecting both IPv4 and IPv6 traffic independently, we define two separate `nf_hook_ops` structures.

```c
// Netfilter hook configuration for IPv4
static struct nf_hook_ops nfho_ipv4 = {
    .hook = ttl_ipv4_hook,               // Callback function for IPv4
    .pf = NFPROTO_IPV4,                  // Target IPv4 protocol family
    .hooknum = NF_INET_PRE_ROUTING,      // Intercept packets before routing decisions
    .priority = NF_IP_PRI_FIRST,         // Execute with the highest priority
};

// Netfilter hook configuration for IPv6
static struct nf_hook_ops nfho_ipv6 = {
    .hook = hop_limit_ipv6_hook,         // Callback function for IPv6
    .pf = NFPROTO_IPV6,                  // Target IPv6 protocol family
    .hooknum = NF_INET_PRE_ROUTING,      // Intercept packets before routing decisions
    .priority = NF_IP6_PRI_FIRST,        // Execute with the highest priority
};
```
---
## 2.2 The Hook Functions and Socket Buffers (`sk_buff`)
The core interception logic is executed by the hook functions, which receive a pointer to the `sk_buff` (socket buffer) structure. The `sk_buff` is the fundamental data structure in the Linux networking stack, containing the packet payload and headers.

```c
/* IPv4 Hook Function */
static unsigned int ttl_ipv4_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *iph = ip_hdr(skb);
    
    if (iph) {
        pr_info("M14 IPv4 Packet - TTL: %u\n", iph->ttl);
    }
    return NF_ACCEPT; // Allow the packet to continue
}

/* IPv6 Hook Function */
static unsigned int hop_limit_ipv6_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct ipv6hdr *ip6h = ipv6_hdr(skb);
    
    if (ip6h) {
        pr_info("M14 IPv6 Packet - Hop Limit: %u\n", ip6h->hop_limit);
    }
    return NF_ACCEPT; // Allow the packet to continue
}
```
---
### 2.3 Key Design Decisions

| Category | Decision | Rationale |
| :--- | :--- | :--- |
| **Netfilter Architecture** | `NF_INET_PRE_ROUTING` Hook | Catches all incoming traffic before routing, ensuring no packets are missed. |
| **Netfilter Architecture** | `NFPROTO_IPV4` & `IPV6` | Explicitly targets both protocol families at the primary hook registration phase. |
| **Netfilter Architecture** | `NF_IP_PRI_FIRST` Priority | Ensures inspection happens immediately, before any other subsystem alters data. |
| **Netfilter Architecture** | `NF_ACCEPT` Return Code | Acts purely as an inspection system; observes traffic without dropping it. |
| **Packet Processing** | `ip_hdr(skb)` Macro | Safely casts packet memory space into a readable `iphdr` structure for IPv4. |
| **Packet Processing** | `skb` Null Check | Prevents kernel panics if a malformed or empty buffer is passed to the hook. |
| **Packet Processing** | `ipv6hdr` Struct Integration | Successfully extracts the `hop_limit` field directly from IPv6 packets. |
| **Logging & Output** | `pr_info(...)` Macro | Uses the modern kernel logging mechanism, preferred over raw `printk`. |
| **Logging & Output** | `dmesg` Log Verification | Provides a lightweight, asynchronous readout of the intercepted TTL data. |
| **Build Environment** | `make -j1` Build Strategy | Prevents OOM killer terminations in the RAM-constrained VM environment. |
| **Build Environment** | Disabling BTF Debug Info | Resolves the fatal `pahole` missing data error during the `vmlinux` linking stage. |
| **Build Environment** | Containerized Build (Podman)| Isolates the compilation toolchain from the host Ubuntu OS. |
| **Module Integration** | Custom `Makefile` | Integrates with the kernel build system (`kbuild`) using `obj-m`. |
| **Module Integration** | Out-of-tree Compilation | Keeps the module source isolated from the main kernel source tree. |
| **Module Integration** | LKM (`.ko`) Format | Allows dynamic insertion (`insmod`) without rebooting the guest VM. |

---

## 3. Project Structure

```text
kernel-playground/
├── kernel/modules/m14_ttl.c    # Netfilter kernel module source code
├── kernel/modules/Makefile     # Modified to include obj-m += m14_ttl.o
└── M14-TTL-Inspection/
    ├── README.md               # This documentation file
    └── ttl_inspection_proof.png          # Execution evidence 
```
---

## 4. Environment Setup & Troubleshooting

### Prerequisites
* **OS:** Ubuntu Linux (Running within a VirtualBox VM)
* **Tools:** Podman, Git
* **Privileges:** Operations must be executed as `root` (`sudo su`) to prevent Git submodule ownership issues.

### Overcoming Environmental Limitations
During the setup of the testbed environment via the provided `./setup-all.sh` script, two critical system constraints were encountered and successfully resolved through manual intervention:

1. **Host Out-Of-Memory (OOM Killer) Intervention:**
   The default `make kbuild` script executes `make -j$(nproc)`, utilizing all available CPU cores. In a resource-constrained VM setup, this exhausted available RAM, causing the kernel to forcefully terminate the build process (`Terminated` / OOM error).
   * **Solution:** The automated script was bypassed. The kernel was manually compiled inside the `kernel/linux` directory using `make -j1`. This forced a single-threaded compilation, sacrificing speed to guarantee stability and successful compilation without memory exhaustion.

2. **BTF Generation Error (Error 255):**
   The kernel build failed at the final linking stage (`vmlinux`) with the error: `FAILED: load BTF from vmlinux: No data available`. The container lacked the `pahole` tools required to generate BPF Type Format (BTF) data.
   * **Solution:** The kernel configuration was manually modified. Using `nano .config`, the setting was changed to `# CONFIG_DEBUG_INFO_BTF is not set`. The kernel was rebuilt successfully. Disabling BTF debug info allowed the custom kernel to compile cleanly without affecting the Netfilter functionality required for this specific task.

## 5. Building the Project

Ensure you are logged in as `root` and operating inside the `kernel-builder` Podman container. The compilation must be done inside the `kernel-builder` Podman container.

**Step 1: Access the Container (Terminal 1)**
Open your first terminal and execute the following commands to start the container and enter it:
> ```bash
> # Navigate to the directory first, before switching to root
> cd ~/kernel-playground/podman
> sudo su
> ./run-detach.sh
> podman exec -it kernel-builder bash
> ```
**Step 2: Compile the Module**
Once inside the container, navigate to the modules directory and build the code:
```bash
cd /opt/kernel-playground/kernel/modules
make clean
make
```
This process compiles `m14_ttl.c` into the loadable kernel object `m14_ttl.ko`. The Makefile automatically copies the compiled module into the `tests/vm/shared` directory, making it accessible to the QEMU virtual machine.

---
## 6. Running the Module
The module must be loaded inside the QEMU Virtual Machine, not in the container. This requires two terminals.

**Step 1: Boot the Virtual Machine**
Still in Terminal 1 (inside the container), launch the QEMU VM:
```bash
podman exec -it kernel-builder bash
cd /opt/kernel-playground/tests/vm
./run.sh
```
(Note: The VM will lock this terminal. Leave it running in the background.) 

**Step 2: Access the VM and Load the Module**
Open a new, second terminal window on your host machine and run:Open Terminal 2, enter the container, connect to the VM via SSH, and insert the module:
```bash
podman exec -it kernel-builder bash
cd /opt/kernel-playground/tests/vm
./enter.sh

insmod /mnt/shared/m14_ttl.ko
```
# 1. Become root and enter the container
sudo su
podman exec -it kernel-builder bash

# 2. SSH into the running QEMU Virtual Machine
cd /opt/kernel-playground/tests/vm
./enter.sh

# 3. Load the custom kernel module
insmod /mnt/shared/m14_ttl.ko
```
A silent return indicates the module was successfully injected into the kernel space.

---

## 7. Testing & Verification

With the module loaded, generate traffic to verify packet interception.

**1. Generate ICMP Traffic:**
Send ping requests to an external server (e.g., Google DNS) to force packets through the networking stack:

```bash
# Generate IPv4 traffic
ping -c 4 8.8.8.8

# Generate IPv6 traffic
ping -6 -c 2 2001:4860:4860::8888
```
**2. Observe Kernel Logs:**
Read the kernel ring buffer to view the outputs generated by the `printk` statements within the Netfilter hook:
```bash
dmesg | tail -n 15
```

**Expected Output:**
The system should successfully log the interception of outgoing/incoming packets along with their corresponding TTL values.

```text
[  546.008458] M14 IPv4 Packet - TTL: 255
[  546.018345] M14 IPv4 Packet - TTL: 64
[  547.008976] M14 IPv4 Packet - TTL: 255
[  547.021411] M14 IPv4 Packet - TTL: 64
[  547.284744] M14 IPv6 Packet - Hop Limit: 255
```

**3. Cleanup:**
To safely remove the module from the kernel and stop packet inspection:
```bash
rmmod m14_ttl
```

*Project submitted as part of the Software Networks course (2025–2026).*
```
