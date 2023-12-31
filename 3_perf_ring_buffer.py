from bcc import BPF
from time import sleep

# eBPF program to run with kernel
program = r"""
BPF_PERF_OUTPUT(perf_output);

struct data_t{
    int pid;
    int uid;
    char command[16];
    char message[12];
};

int count_invocations_per_uid(void *ctx){
    struct data_t data = {};
    char message[12] = "Hello world";

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);

    perf_output.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Attach eBPF C program to "execve" syscall
b = BPF(text=program)
syscall_execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall_execve, fn_name="count_invocations_per_uid")

# user-space main function to be triggered with ebpf call
def print_event(cpu, data, size):
    data = b["perf_output"].event(data)
    print(f"{data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

# Set handler function
b["perf_output"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()
