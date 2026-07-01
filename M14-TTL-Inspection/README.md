# Software Networks Project: M14 – Packet TTL Inspection (Netfilter)

**Author:** Marta Rolbiecka [0383386]
**Level:** Kernel Module Development
**Course:** Software Networks (2025-2026)

## Table of Contents
1. Project Overview
2. Code Architecture & Data Structures
3. Project Structure
4. Environment Setup & Troubleshooting
5. Building the Project
6. Running the Module
7. Testing & Verification

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
nfho.priority = NF_IP_PRI_FIRST;             // Priority: highest, run before other hooks
