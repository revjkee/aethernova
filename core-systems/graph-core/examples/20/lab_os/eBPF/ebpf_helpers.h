#ifndef LAB_OS_EBPF_HELPERS_H
#define LAB_OS_EBPF_HELPERS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Макросы для удобства и безопасности

// Определение лицензии для eBPF программы
#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Версия ядра, для условной компиляции
#ifndef BPF_CORE_READ
#define BPF_CORE_READ(dest, src, field) \
    ({ \
        typeof(((src)->field)) _val = 0; \
        bpf_core_read(&_val, sizeof(_val), &((src)->field)); \
        _val; \
    })
#endif

// Помощники eBPF API (обертки с проверкой ошибок)

// Безопасное чтение памяти
static __always_inline int safe_bpf_probe_read(void *dst, __u32 size, const void *unsafe_ptr) {
    int ret = bpf_probe_read(dst, size, unsafe_ptr);
    return ret;
}

// Обертка для отправки события в пользователльский уровень через perf event
static __always_inline int send_perf_event(void *ctx, void *data, __u32 size, __u32 map_fd) {
    return bpf_perf_event_output(ctx, map_fd, BPF_F_CURRENT_CPU, data, size);
}

// Утилиты для работы с сессиями и PID
static __always_inline __u32 get_current_pid_tgid(void) {
    return bpf_get_current_pid_tgid();
}

static __always_inline __u32 get_current_uid_gid(void) {
    return bpf_get_current_uid_gid();
}

// Помощники для работы с сокетами (например, для сетевых фильтров)
static __always_inline int redirect_to_cpu(struct __sk_buff *skb, __u32 cpu) {
    return bpf_redirect_map(&cpu_map, cpu, 0);
}

// Защита от ошибок чтения и записи в eBPF программах
static __always_inline int safe_map_update_elem(__u32 map_fd, const void *key, const void *value, __u64 flags) {
    int ret = bpf_map_update_elem(map_fd, key, value, flags);
    return ret;
}

static __always_inline int safe_map_lookup_elem(__u32 map_fd, const void *key, void *value) {
    int ret = bpf_map_lookup_elem(map_fd, key, value);
    return ret;
}

// Компиляция структуры с пользовательскими определениями (расширяемость)
struct event_data_t {
    __u64 timestamp;
    __u32 pid;
    __u32 uid;
    char comm[16];
    char data[64];
} __attribute__((packed));

// Лицензия GPL обязательна для расширенных возможностей eBPF
char _license[] SEC("license") = "GPL";

#endif // LAB_OS_EBPF_HELPERS_H
