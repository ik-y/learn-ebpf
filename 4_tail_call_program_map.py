from bcc import BPF
from time import sleep
import ctypes

# eBPF program to run with kernel
program = r"""
BPF_PROG_ARRAY(syscall, 300);

int entrypoint(struct bpf_raw_tracepoint_args *ctx){
  int opcode = ctx -> args[1];
  syscall.call(ctx, opcode);
  bpf_trace_printk("Unhamndled syscall: %d", opcode);
  return 0;
}

int execve(void *ctx){
  bpf_trace_printk("execve");
}

int timer(void *ctx){
  bpf_trace_printk("timer");
}

int ignore(void *ctx){
  return 0;
}
"""

# Attach eBPF C program to any syscall enter
b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="entrypoint")

ignore_fn = b.load_func("ignore", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("timer", BPF.RAW_TRACEPOINT)
execve_fn = b.load_func("execve", BPF.RAW_TRACEPOINT)

# Map syscall number to function
function_map = b.get_table("syscall")
function_map[ctypes.c_int(59)] = ctypes.c_int(execve_fn.fd)
function_map[ctypes.c_int(228)] = ctypes.c_int(timer_fn.fd)

# Wait for events
b.trace_print()
