# M14 - Packet TTL Inspection (Netfilter Kernel Module)

## 1. Project Description and Results
The objective of this project (M14) was to develop a custom Linux kernel module that uses the Netfilter subsystem to intercept network packets and extract specific header fields. Specifically, the module intercepts IPv4 and IPv6 traffic and logs the Time-To-Live (TTL) or Hop Limit values to the kernel ring buffer.

### Experimental Outcomes
The module was successfully compiled and loaded into a custom micro-VM environment (QEMU) running a freshly built kernel (6.12.x). When network traffic was generated (e.g., using `ping 8.8.8.8`), the module successfully intercepted the packets and logged the correct TTL values.

**Evidence of execution (Kernel Logs):**
```text
root@vmtest:~# ping -c 4 8.8.8.8
...
root@vmtest:~# dmesg | tail -n 10
[  546.008458] M14 IPv4 Packet - TTL: 255
[  546.018345] M14 IPv4 Packet - TTL: 64
[  547.008976] M14 IPv4 Packet - TTL: 255
[  547.021411] M14 IPv4 Packet - TTL: 64
[  547.284744] M14 IPv6 Packet - Hop Limit: 255
(Zrób zrzut ekranu ze swojego terminala pokazujący ping i wynik dmesg i dodaj go tutaj w repozytorium jako plik graficzny, np. ![Wynik dmesg](img/screenshot1.png))

2. Instructions for Replicating the Experiments
To replicate this environment and test the module, follow these exact steps. Ensure you are operating as the root user to avoid Git ownership issues with the submodules.

A. Environment Setup
Log in as root on your host system: sudo su

Clone this repository and navigate to the podman directory.

Build the container image and setup the infrastructure:

Bash
./container-build.sh
./setup-all.sh
(Note: If the setup-all.sh script is terminated by the OOM Killer due to limited host RAM, refer to the Troubleshooting section below).

Start the container and enter it:

Bash
podman start kernel-builder
podman exec -it kernel-builder bash
B. Compiling the Module
Inside the container, navigate to the modules directory and build the out-of-tree module:

Bash
cd /opt/kernel-playground/kernel/modules
make clean
make
The resulting m14_ttl.ko file is automatically copied to tests/vm/shared.

C. Running and Testing
Start the VM: In your current terminal, start the QEMU virtual machine:

Bash
cd /opt/kernel-playground/tests/vm
./run.sh
Access the VM: Open a second terminal on your host, log in as root, enter the container, and connect to the VM:

Bash
podman exec -it kernel-builder bash
cd /opt/kernel-playground/tests/vm
./enter.sh
Load the Module: Inside the VM guest OS, insert the module:

Bash
insmod /mnt/shared/m14_ttl.ko
Generate Traffic & Verify: Generate ICMP traffic and check the kernel logs:

Bash
ping -c 4 8.8.8.8
dmesg | tail -n 20
3. Development Notes and Implementation Details
Design Choices
Netfilter Hooks: The module registers a hook function with Netfilter (e.g., at NF_INET_PRE_ROUTING or NF_INET_LOCAL_IN). This allows interception of the sk_buff structure before it reaches the application layer.

Header Parsing: Inside the hook, the module checks the protocol family. For AF_INET (IPv4), it extracts the iphdr struct to read the ttl field. For AF_INET6 (IPv6), it extracts the ipv6hdr struct to read the hop_limit field.

Logging: Values are logged using printk() with KERN_INFO log level, ensuring they are easily readable via dmesg.

Troubleshooting and Overcoming Environment Limitations
During the setup of the VM and kernel compilation, two major environmental constraints were encountered and resolved:

Host Out-Of-Memory (OOM) / Terminated Build:
The default make kbuild script uses make -j$(nproc), which exhausted the RAM on the host virtual machine, causing the Linux OOM killer to terminate the build process.

Solution: The kernel compilation was performed manually bypassing the variable, using a single thread to guarantee stability:
cd kernel/linux && make -j1.

BTF Generation Error (Error 255):
The kernel build failed at the final linking stage (vmlinux) with the error: FAILED: load BTF from vmlinux: No data available. This occurred because the container lacked the necessary pahole tools to generate BPF Type Format (BTF) data.

Solution: The kernel configuration was manually modified to exclude BTF generation. Using nano .config, the setting was changed to # CONFIG_DEBUG_INFO_BTF is not set. The kernel was then successfully rebuilt. This design choice allowed the custom kernel to compile cleanly in a resource-constrained container without affecting the Netfilter functionality required for the M14 task.
