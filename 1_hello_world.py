from bcc import BPF

# eBPF program to run with kernel
program = r"""
int hello(void *ctx){
    bpf_trace_printk("Hello, world!");
    return 0;
}
"""

# Attach eBPF C program to "execve" syscall
b = BPF(text=program)
syscall_execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall_execve, fn_name="hello")

# Print tracing result
# execve runs program, so new program run will cause log "Hello, world!"
b.trace_print()

