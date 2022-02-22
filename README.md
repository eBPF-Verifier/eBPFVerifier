# eBPF Verifier

The Berkeley Packet Filter (eBPF) enables user space programs to execute in the Linux kernel. 

Before eBPF, kernel code was mainly released as kernel patches and kernel modules. The eBPF enables program to be loaded from user space and run in kernel space. Some insecure programs might be introduced by these eBPF programs during this process. 

Thus, an eBPF verifier is needed to conduct static analysis to reject and disapprove the insecure programs executing in kernel address space. 

eBPF verifier is an event driven framework, where the events are triggered by kernel hooks. 
Hooks monitors:
(1) syscalls, 
(2) function entry and exit, 
(3) network events and 
(4) kprobes and uprobes. 

The current set of eBPF program types supported by the kernel is as following:

```
- BPF_PROG_TYPE_SOCKET_FILTER: a network packet filter
- BPF_PROG_TYPE_KPROBE: determine whether a kprobe should fire or not
- BPF_PROG_TYPE_SCHED_CLS: a network traffic-control classifier
- BPF_PROG_TYPE_SCHED_ACT: a network traffic-control action
- BPF_PROG_TYPE_TRACEPOINT: determine whether a tracepoint should fire or not
- BPF_PROG_TYPE_XDP: a network packet filter run from the device-driver receive path
- BPF_PROG_TYPE_PERF_EVENT: determine whether a perf event handler should fire or not
- BPF_PROG_TYPE_CGROUP_SKB: a network packet filter for control groups
- BPF_PROG_TYPE_CGROUP_SOCK: a network packet filter for control groups that is allowed to modify socket options
- BPF_PROG_TYPE_LWT_*: a network packet filter for lightweight tunnels
- BPF_PROG_TYPE_SOCK_OPS: a program for setting socket parameters
- BPF_PROG_TYPE_SK_SKB: a network packet filter for forwarding packets between sockets
- BPF_PROG_CGROUP_DEVICE: determine if a device operation should be permitted or not
```


Currently the eBPF verifier is focusing on verifying/validating "function entry and exit".


There are two passes in eBPF verifier:

-  1. DAG checks, uses depth first search to check if the bytecode of eBPF program could be parsed into a DAG, and check DAG for unreachable instructions and worst execution time. 

- 2. FSM checks, creates finite state machines, explore all execution paths from the entry instruction of eBPF program, verifies and monitors if states present valid/correct behaviors. 

eBPF verifier builds and checks the control flow graph (i.e. a Directed Acyclic Graph) of programs, and verifies/validates the function calls. 

It also simulates instruction execution and monitors state change of registers and stack. 

The calls to unknown functions and unresolved function calls will be rejected.

For example, eBPF confirms program ends with BPF_EXIT, and confirms all branch instructions, except for BPF_EXIT and BPF_CALL, are within program bounds. 




