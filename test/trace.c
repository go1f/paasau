#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>

struct event {
    u32 pid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct event e = {};

    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read(&e.saddr, sizeof(e.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read(&e.daddr, sizeof(e.daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read(&e.sport, sizeof(e.sport), &sk->__sk_common.skc_num);
    bpf_probe_read(&e.dport, sizeof(e.dport), &sk->__sk_common.skc_dport);

    e.dport = __builtin_bswap16(e.dport);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
