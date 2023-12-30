from bcc import BPF

program = r"""
int hello(void *ctx){
    bpf_trace_printk("Hello, world!");
    return 0;
}
"""

b = BPF(text=program)
syscall_execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall_execve, fn_name="hello")

b.trace_print()

