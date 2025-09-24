// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

struct event {
    u32 pid;
    u64 timestamp_ns;
    u64 syscall_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Хук на системный вызов sys_enter
SEC("tracepoint/syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    struct event evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.syscall_id = ctx->id;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
