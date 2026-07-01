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

### 2.1 The Netfilter Hook Structure
To intercept packets, the module registers a callback function using the Netfilter framework. This requires defining an `nf_hook_ops` structure.

```c
static struct nf_hook_ops nfho;

nfho.hook = hook_func;                       // Function to call when a packet arrives
nfho.hooknum = NF_INET_PRE_ROUTING;          // Hook point: immediately after packet reception
nfho.pf = PF_INET;                           // Protocol family: IPv4 (and adaptable to IPv6)
nfho.priority = NF_IP_PRI_FIRST;             // Priority: highest, run before other hooks### 2.2 The Hook Function and Socket Buffers (`sk_buff`)
The core interception logic is executed by the hook function, which receives a pointer to the `sk_buff` (socket buffer) structure. The `sk_buff` is the fundamental data structure in the Linux networking stack, containing the packet payload and headers.

```c
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;

    // Safety check: ensure the socket buffer is not null
    if (!skb) return NF_ACCEPT;

    // Extract the network layer header
    ip_header = ip_hdr(skb);

    if (ip_header) {
        // Print the TTL value to the kernel ring buffer
        printk(KERN_INFO "M14 IPv4 Packet - TTL: %d\n", ip_header->ttl);
    }

    return NF_ACCEPT; // Allow the packet to continue its journey
}
```

### 2.3 Key Design Decisions

| Category | Decision | Rationale |
| :--- | :--- | :--- |
| **Netfilter Architecture** | `NF_INET_PRE_ROUTING` Hook | Catches all incoming traffic before routing, ensuring no packets are missed due to local routing rules. |
| **Netfilter Architecture** | `PF_INET` Protocol Family | Targets IPv4 traffic specifically at the primary Netfilter hook registration phase. |
| **Netfilter Architecture** | `NF_IP_PRI_FIRST` Priority | Ensures inspection happens immediately, before any other subsystem alters the packet data. |
| **Netfilter Architecture** | `NF_ACCEPT` Return Code | Acts purely as an Intrusion Detection/Inspection system. It observes traffic but does not drop (`NF_DROP`) or alter it. |
| **Packet Processing** | `ip_hdr(skb)` Macro | Safely casts the network layer portion of the `sk_buff` memory space into a readable `iphdr` structure. |
| **Packet Processing** | `skb` Null Check | Prevents catastrophic kernel panics if a malformed or empty buffer is passed to the hook. |
| **Packet Processing** | `ipv6hdr` Struct Ready | Prepares the codebase architecture for extracting the `hop_limit` field from IPv6 packets. |
| **Logging & Output** | `printk(KERN_INFO ...)` | Uses the kernel's internal logging mechanism. Observable via `dmesg` without requiring any user-space daemon. |
| **Logging & Output** | `dmesg` Log Verification | Provides a lightweight, non-blocking, and asynchronous readout of the intercepted TTL data. |
| **Build Environment** | `make -j1` Build Strategy | Prevents Out-Of-Memory (OOM) killer terminations in the RAM-constrained VM environment. |
| **Build Environment** | Disabling BTF Debug Info | Resolves the fatal `pahole` missing data error during the final `vmlinux` linking stage. |
| **Build Environment** | Containerized Build (Podman) | Isolates the compilation toolchain and required dependencies entirely from the host Ubuntu OS. |
| **Module Integration** | Custom `Makefile` | Integrates with the existing kernel build system (`kbuild`) seamlessly using `obj-m`. |
| **Module Integration** | Out-of-tree Compilation | Keeps the module source independent and isolated from the massive main kernel source tree. |
| **Module Integration** | LKM (.ko) Format | Allows for dynamic insertion (`insmod`) and removal (`rmmod`) without rebooting the guest VM. |

## 3. Project Structure

```text
kernel-playground/
├── kernel/modules/m14_ttl.c    # Netfilter kernel module source code
├── kernel/modules/Makefile     # Modified to include obj-m += m14_ttl.o
└── M14-TTL-Inspection/
    ├── README.md               # This documentation file
    └── screenshot.png          # Execution evidence (add your image here)
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
   * **Solution:** The kernel configuration was manually modified. Using `nano .config`, the setting was changed to `# CONFIG_DEBUG_INFO_BTF is not set`. The kernel was rebuilt successfully. Disabling BTF debug info allowed the custom kernel to compile cleanly without affecting the Netfilter functionality required for this specific task.---

## 5. Building the Project

Ensure you are logged in as root and operating inside the `kernel-builder` Podman container.

Navigate to the modules directory and invoke the Makefile:
```bash
cd /opt/kernel-playground/kernel/modules
make clean
make
```
This process compiles `m14_ttl.c` into the loadable kernel object `m14_ttl.ko`. The Makefile automatically copies the compiled module into the `tests/vm/shared` directory, making it accessible to the QEMU virtual machine.

---

## 6. Running the Module

The module must be executed strictly within the testbed VM (Guest OS) running the freshly compiled custom kernel, not on the Host OS.

**Step 1: Boot the Virtual Machine**
In Terminal 1 (inside the container), launch the QEMU VM:
```bash
cd /opt/kernel-playground/tests/vm
./run.sh
```

**Step 2: Access the VM and Load the Module**
Open Terminal 2, enter the container, connect to the VM via SSH, and insert the module:
```bash
podman exec -it kernel-builder bash
cd /opt/kernel-playground/tests/vm
./enter.sh

insmod /mnt/shared/m14_ttl.ko
```
A silent return indicates the module was successfully injected into the kernel space.

---

## 7. Testing & Verification

With the module loaded, generate traffic to verify packet interception.

**1. Generate ICMP Traffic:**
Send ping requests to an external server (e.g., Google DNS) to force packets through the networking stack:
```bash
ping -c 4 8.8.8.8
```

**2. Observe Kernel Logs:**
Read the kernel ring buffer to view the outputs generated by the `printk` statements within the Netfilter hook:
```bash
dmesg | tail -n 20
```

**Expected Output:**
The system successfully logs the interception of outgoing/incoming packets along with their corresponding TTL values.

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

By binding to `NF_INET_PRE_ROUTING`, the module guarantees that every incoming packet is inspected before any routing decisions are made by the Linux kernel.
