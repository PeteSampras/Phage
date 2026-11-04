// SPDX-License-Identifier: GPL-2.0
/*
 * selfprotect.bpf.c — agent self-protection (tamper-resistance) via eBPF-LSM.
 * Where sensors.bpf.c *detects* an attack on the agent, this *denies* it: an
 * lsm/task_kill hook refuses a lethal/stop signal aimed at the agent from an
 * unauthorized sender, so an attacker cannot blind Phage by killing it.
 *
 * Separate object, loaded only when self-protection is armed (mode enforce + enforcement.self_protect) AND the kernel has
 * BPF LSM active — so phaged still starts everywhere else.
 *
 * Safety (this project has a lockout scar): enforcement is inert unless `protect`
 * is 1, and the agent's own pid, its launcher (ppid), and pid 1 (systemd/init)
 * are ALWAYS allowed to signal it. So `systemctl stop` (sent by pid 1) and a
 * reboot are always a guaranteed way to stop the agent — it can never truly lock
 * the box out. Detaching the program (agent exit) also lifts all enforcement.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM 1

#define SIG_INT 2
#define SIG_QUIT 3
#define SIG_KILL 9
#define SIG_TERM 15
#define SIG_STOP 19

#define SLOT(name)                       \
	struct {                         \
		__uint(type, BPF_MAP_TYPE_ARRAY); \
		__uint(max_entries, 1);  \
		__type(key, __u32);      \
		__type(value, __u32);    \
	} name SEC(".maps")

SLOT(sp_self_pid);  /* the agent's tgid */
SLOT(sp_self_ppid); /* the agent's launcher pid (always allowed) */
SLOT(sp_protect);   /* 0 = inert (allow all), 1 = enforce */

static __always_inline __u32 slot(void *m)
{
	__u32 zero = 0;
	__u32 *v = bpf_map_lookup_elem(m, &zero);
	return v ? *v : 0;
}

SEC("lsm/task_kill")
int BPF_PROG(guard_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred, int ret)
{
	if (ret)
		return ret; /* respect an earlier LSM's decision */

	__u32 self = slot(&sp_self_pid);
	if (!self || BPF_CORE_READ(p, tgid) != self)
		return 0; /* not aimed at the agent */
	if (!slot(&sp_protect))
		return 0; /* enforcement disarmed */

	__u32 sender = bpf_get_current_pid_tgid() >> 32;
	if (sender == self || sender == 1 || sender == slot(&sp_self_ppid))
		return 0; /* self, init/systemd, and the launcher are always allowed */

	if (sig == SIG_KILL || sig == SIG_TERM || sig == SIG_STOP ||
	    sig == SIG_INT || sig == SIG_QUIT)
		return -EPERM; /* deny the tamper */
	return 0;
}
