from bcc import BPF

# eBPF program to run with kernel
program = r"""
int hello(void *ctx){
  bpf_trace_printk("Hello, world!");
  return 0;
}
"""

# Attach eBPF C program to some syscalls
# Attaching to read, write, openat might cause log flooding
b = BPF(text=program)
syscall_execve = b.get_syscall_fnname("execve")
syscall_openat = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")
syscall_read = b.get_syscall_fnname("read")
syscall_close = b.get_syscall_fnname("close")
b.attach_kprobe(event=syscall_execve, fn_name="hello")
#b.attach_kprobe(event=syscall_openat, fn_name="hello")
#b.attach_kprobe(event=syscall_write, fn_name="hello")
#b.attach_kprobe(event=syscall_read, fn_name="hello")
b.attach_kprobe(event=syscall_close, fn_name="hello")

# Print tracing result
# execve runs program, so new program run will cause log "Hello, world!"
b.trace_print()
