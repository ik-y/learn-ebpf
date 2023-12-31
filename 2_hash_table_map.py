from bcc import BPF
from time import sleep

# eBPF program to run with kernel
program = r"""
BPF_HASH(counter_table);

int count_invocations_per_uid(void *ctx){
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table.lookup(&uid);

    if(p != 0){
        counter = *p;
    }
    counter++;
    counter_table.update(&uid, &counter);
    return 0;
}
"""

# Attach eBPF C program to "execve" syscall
b = BPF(text=program)
syscall_execve = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall_execve, fn_name="count_invocations_per_uid")

# Fetch hash table per 2 seconds
while True:
    sleep(2)
    s = ""
    for key, value in b["counter_table"].items():
        s += f"ID {key.value}: {value.value}\t"
    print(s)
