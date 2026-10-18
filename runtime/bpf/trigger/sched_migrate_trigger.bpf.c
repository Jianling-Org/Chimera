// SPDX-License-Identifier: GPL-2.0
/*
 * sched_migrate_trigger.bpf.c
 * ===========================
 * 板端 Chimera 迁移触发程序（bpftool prog id 19 "tracepoint_handler"，
 * 挂 sched:sched_migrate_task）的等价重建。
 *
 * 依据：
 *  - 板端 `bpftool prog dump xlated id 19` 反汇编（29 条指令，见 README.md）
 *  - 内核 kfunc 语义（chimera-kernel kernel/bpf/helpers_chimera.c:702-788）
 *  - 本树 include/trace/events/sched.h 的 sched_migrate_task 字段布局
 *    （__string(comm) 4B + pid@12 + prio@16 + orig_cpu@20 + dest_cpu@24，
 *      与反汇编读出的 +12/+20/+24 完全一致）
 *
 * 加载/挂载步骤见 README.md。关键前提：
 *  - 内核须含 kfunc bpf_xdp_get_xfrm_state_chimera（即 helpers_chimera.c 已编译）
 *  - uprobe_info_map 必须复用注册侧 pin 的 /sys/fs/bpf/pid_uprobe_map
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/*
 * map id 1（板端）：uprobe_info_map —— HASH, key=u32, value=176B。
 * struct chimera_migration_target_info 来自目标内核生成的 vmlinux.h。
 * 注册侧（chimera-user）写入 /sys/fs/bpf/pid_uprobe_map；
 * 加载本程序时必须用 pinned map 复用同一 map 对象，
 * 否则内核 map_worker 拿不到注册数据。
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, struct chimera_migration_target_info);
} uprobe_info_map SEC(".maps");

/* map id 2（板端）：ringbuf —— 纯观测日志，不影响触发 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 板端实际大小未知，1MB 为合理值 */
} ringbuf SEC(".maps");

/* 24B 事件；字段偏移仍为 0、4、8、16、20 */
struct migrate_event {
	__u32 current_tgid;	/* 当前上下文 tgid，不一定是迁移目标 */
	__u32 kfunc_result;	/* 通常为 0；找不到 ctx->pid 时为该 pid */
	__u64 timestamp;/* bpf_ktime_get_ns() */
	__u32 dest_cpu;
	__u32 orig_cpu;
};

extern pid_t bpf_xdp_get_xfrm_state_chimera(pid_t pid, void *map, int dst_cpu) __ksym;

SEC("tracepoint/sched/sched_migrate_task")
int tracepoint_handler(struct trace_event_raw_sched_migrate_task *ctx)
{
	struct migrate_event *ev;
	pid_t res;

	/* 核心：把每次任务迁移喂给 kfunc（tgid 过滤 + 跨界匹配 + 信号 41 由内核侧做） */
	res = bpf_xdp_get_xfrm_state_chimera(ctx->pid, &uprobe_info_map, ctx->dest_cpu);

	/* 旁路观测日志（原程序行为，可整体删除而不影响触发） */
	ev = bpf_ringbuf_reserve(&ringbuf, sizeof(*ev), 0);
	if (!ev)
		return 0;

	ev->current_tgid = bpf_get_current_pid_tgid() >> 32;
	ev->timestamp = bpf_ktime_get_ns();
	ev->kfunc_result = res;
	ev->orig_cpu = ctx->orig_cpu;
	ev->dest_cpu = ctx->dest_cpu;

	bpf_ringbuf_submit(ev, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
