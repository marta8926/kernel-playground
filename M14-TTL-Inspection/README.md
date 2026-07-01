Software Networks Project: M14 – Packet TTL Inspection (Netfilter)Author: Marta Rolbiecka [0383386]Level: Kernel Module DevelopmentCourse: Software Networks (2025-2026)Table of ContentsProject OverviewCode Architecture & Data StructuresProject StructureEnvironment Setup & TroubleshootingBuilding the ProjectRunning the ModuleTesting & Verification1. Project OverviewThis project implements a custom Linux Kernel Module (LKM) designed to inspect network traffic at the kernel level. The core objective of the M14 task is to utilize the Linux Netfilter subsystem to intercept routing packets (both IPv4 and IPv6) and extract their Time-To-Live (TTL) or Hop Limit values before they are processed by the higher levels of the network stack.Unlike user-space packet sniffers (like Wireshark/tcpdump) which rely on packet copying via libpcap, this implementation operates entirely within kernel space. It hooks directly into the networking stack, ensuring deep inspection with minimal overhead. The project is executed and tested within a custom QEMU micro-VM environment orchestrated by Podman.2. Code Architecture & Data StructuresAll packet processing logic is encapsulated within a single kernel module (m14_ttl.c). Below is a detailed breakdown of the key kernel APIs and structures utilized.2.1 The Netfilter Hook StructureTo intercept packets, the module registers a callback function using the Netfilter framework. This requires defining an nf_hook_ops structure.Cstatic struct nf_hook_ops nfho;

nfho.hook = hook_func;                       // Function to call when a packet arrives
nfho.hooknum = NF_INET_PRE_ROUTING;          // Hook point: immediately after packet reception
nfho.pf = PF_INET;                           // Protocol family: IPv4 (and adaptable to IPv6)
nfho.priority = NF_IP_PRI_FIRST;             // Priority: highest, run before other hooks
By binding to NF_INET_PRE_ROUTING, the module guarantees that every incoming packet is inspected before any routing decisions are made by the Linux kernel.2.2 The Hook Function and Socket Buffers (sk_buff)The core interception logic is executed by the hook function, which receives a pointer to the sk_buff (socket buffer) structure. The sk_buff is the fundamental data structure in the Linux networking stack, containing the packet payload and headers.Cunsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
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
2.3 Key Design DecisionsDecisionRationaleNF_INET_PRE_ROUTING HookCatches all incoming traffic before routing, ensuring no packets are missed due to local routing rules.ip_hdr(skb) MacroSafely casts the network layer portion of the sk_buff memory space into a readable iphdr structure.printk(KERN_INFO ...)Uses the kernel's internal logging mechanism. Observable via dmesg without requiring any user-space daemon.NF_ACCEPT Return CodeActs purely as an Intrusion Detection/Inspection system. It observes traffic but does not drop (NF_DROP) or alter it.PF_INET Protocol FamilyTargets IPv4 traffic specifically at the primary Netfilter hook registration phase.NF_IP_PRI_FIRST PriorityEnsures inspection happens immediately, before any other subsystem alters the packet data.Custom MakefileIntegrates with the existing kernel build system (kbuild) seamlessly using obj-m.Out-of-tree CompilationKeeps the module source independent and isolated from the massive main kernel source tree.make -j1 Build StrategyPrevents Out-Of-Memory (OOM) killer terminations in the RAM-constrained VM environment.Disabling BTF Debug InfoResolves the fatal pahole missing data error during the final vmlinux linking stage.skb Null CheckPrevents catastrophic kernel panics if a malformed or empty buffer is passed to the hook.dmesg Log VerificationProvides a lightweight, non-blocking, and asynchronous readout of the intercepted TTL data.LKM (.ko) FormatAllows for dynamic insertion (insmod) and removal (rmmod) without rebooting the guest VM.ipv6hdr Struct ReadyPrepares the codebase architecture for extracting the hop_limit field from IPv6 packets.Containerized Build (Podman)Isolates the compilation toolchain and required dependencies entirely from the host Ubuntu OS.3. Project StructurePlaintextkernel-playground/
├── kernel/modules/m14_ttl.c    # Netfilter kernel module source code
├── kernel/modules/Makefile     # Modified to include obj-m += m14_ttl.o
└── M14-TTL-Inspection/
    ├── README.md               # This documentation file
    └── screenshot.png          # Execution evidence (add your image here)
4. Environment Setup & TroubleshootingPrerequisitesOS: Ubuntu Linux (Running within a VirtualBox VM)Tools: Podman, GitPrivileges: Operations must be executed as root (sudo su) to prevent Git submodule ownership issues.Overcoming Environmental LimitationsDuring the setup of the testbed environment via the provided ./setup-all.sh script, two critical system constraints were encountered and successfully resolved through manual intervention:Host Out-Of-Memory (OOM Killer) Intervention:The default make kbuild script executes make -j$(nproc), utilizing all available CPU cores. In a resource-constrained VM setup, this exhausted available RAM, causing the kernel to forcefully terminate the build process (Terminated / OOM error).Solution: The automated script was bypassed. The kernel was manually compiled inside the kernel/linux directory using make -j1. This forced a single-threaded compilation, sacrificing speed to guarantee stability and successful compilation without memory exhaustion.BTF Generation Error (Error 255):The kernel build failed at the final linking stage (vmlinux) with the error: FAILED: load BTF from vmlinux: No data available. The container lacked the pahole tools required to generate BPF Type Format (BTF) data.Solution: The kernel configuration was manually modified. Using nano .config, the setting was changed to # CONFIG_DEBUG_INFO_BTF is not set. The kernel was rebuilt successfully. Disabling BTF debug info allowed the custom kernel to compile cleanly without affecting the Netfilter functionality required for this specific task.5. Building the ProjectEnsure you are logged in as root and operating inside the kernel-builder Podman container.Navigate to the modules directory and invoke the Makefile:Bashcd /opt/kernel-playground/kernel/modules
make clean
make
This process compiles m14_ttl.c into the loadable kernel object m14_ttl.ko. The Makefile automatically copies the compiled module into the tests/vm/shared directory, making it accessible to the QEMU virtual machine.6. Running the ModuleThe module must be executed strictly within the testbed VM (Guest OS) running the freshly compiled custom kernel, not on the Host OS.Step 1: Boot the Virtual MachineIn Terminal 1 (inside the container), launch the QEMU VM:Bashcd /opt/kernel-playground/tests/vm
./run.sh
Step 2: Access the VM and Load the ModuleOpen Terminal 2, enter the container, connect to the VM via SSH, and insert the module:Bashpodman exec -it kernel-builder bash
cd /opt/kernel-playground/tests/vm
./enter.sh

insmod /mnt/shared/m14_ttl.ko
A silent return indicates the module was successfully injected into the kernel space.7. Testing & VerificationWith the module loaded, generate traffic to verify packet interception.1. Generate ICMP Traffic:Send ping requests to an external server (e.g., Google DNS) to force packets through the networking stack:Bashping -c 4 8.8.8.8
2. Observe Kernel Logs:Read the kernel ring buffer to view the outputs generated by the printk statements within the Netfilter hook:Bashdmesg | tail -n 20
Expected Output:The system successfully logs the interception of outgoing/incoming packets along with their corresponding TTL values.Plaintext[  546.008458] M14 IPv4 Packet - TTL: 255
[  546.018345] M14 IPv4 Packet - TTL: 64
[  547.008976] M14 IPv4 Packet - TTL: 255
[  547.021411] M14 IPv4 Packet - TTL: 64
[  547.284744] M14 IPv6 Packet - Hop Limit: 255
3. Cleanup:To safely remove the module from the kernel and stop packet inspection:Bashrmmod m14_ttl
Project submitted as part of the Software Networks course (2025–2026).
