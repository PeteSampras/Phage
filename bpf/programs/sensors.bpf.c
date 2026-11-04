// SPDX-License-Identifier: GPL-2.0
/*
 * sensors.bpf.c — Phage's kernel sensor set, compiled as a single object so all
 * programs share one ring buffer map (userspace then has one reader).
 *
 *   on_commit_creds : privilege transitions — a process becoming root.
 *   on_sched_exec   : process executions — a service spawning a shell is the
 *                     universal effect of RCE (PHP/Node/command injection/
 *                     SQLi->OS), caught as a never-before-seen parent->child pair.
 *   on_tcp_connect  : outbound connections — a reverse shell or C2 beacon is the
 *                     universal effect of a foothold phoning home, caught as a
 *                     program that has no history of egressing suddenly dialing out.
 *   on_file_open    : write-opens of persistence/credential files — a webshell
 *                     dropped into the web root, a key appended to
 *                     authorized_keys, a cron job planted. The universal effect
 *                     of an attacker digging in, caught as a program writing an
 *                     artifact class it has never written on this host.
 *   on_*_enable     : high-risk kernel-enabling operations (unprivileged user
 *                     namespaces, eBPF loads, io_uring, userfaultfd) — the setup
 *                     an exploit does *before* it escalates. Caught as a program
 *                     performing an enabling op it has no history of on this host.
 *
 * Author anywhere; build + attach on Linux with CO-RE (needs kernel BTF). See
 * docs/guides/development.md.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "common/events.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Address families. These live in UAPI headers, not in kernel BTF, so the
 * CO-RE object has to define them itself. */
#define AF_INET  2
#define AF_INET6 10

/* FMODE_WRITE lives in a kernel header (include/linux/fs.h), not in BTF, so the
 * CO-RE object defines it itself. It is set on any file opened for writing. */
#define FMODE_WRITE 0x2

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} phage_events SEC(".maps");

/* phage_drops counts events a sensor saw but could not hand to userspace
 * because bpf_ringbuf_reserve failed (the ring buffer was full: phaged is not
 * draining it fast enough, or it is wedged). A blinded sensor is silent; a
 * drop counter makes that silence visible. Per-CPU, so the hot path never
 * contends; userspace sums the slots (phage status, the heartbeat record). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} phage_drops SEC(".maps");

/* reserve_event reserves one event slot, counting a failed reservation. Every
 * sensor reserves through here. The add is atomic: a sensor in interrupt
 * context (signal_generate) can preempt another on the same CPU. */
static __always_inline struct phage_event *reserve_event(void)
{
	struct phage_event *e = bpf_ringbuf_reserve(&phage_events, sizeof(*e), 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&phage_drops, &zero);
		if (n)
			__sync_fetch_and_add(n, 1);
	}
	return e;
}

/* honeytokens maps a decoy file's inode number -> 1. Userspace plants the decoys
 * (fake credential files nothing legitimate references) and registers their
 * inodes; any open of one is a near-zero-false-positive sign of an intruder
 * snooping for secrets. ht_armed gates the per-open inode read so there is no
 * cost when honeytokens are not in use. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, __u64);
	__type(value, __u8);
} honeytokens SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} ht_armed SEC(".maps");

/* self_pid holds the Phage agent's own tgid, written by userspace at startup, so
 * the self-defense programs can tell a tamper attempt against the agent from any
 * other signal/ptrace on the box. 0 = unset (self-defense inert). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} self_pid SEC(".maps");

static __always_inline __u32 phage_self_pid(void)
{
	__u32 zero = 0;
	__u32 *p = bpf_map_lookup_elem(&self_pid, &zero);
	return p ? *p : 0;
}

/* Per-CPU scratch for inspecting a process's environment at exec: the env region
 * is larger than the 512-byte eBPF stack, so it lives in a map. We scan a bounded
 * window from its start; a hijack var past the window is a documented gap. */
#define ENV_SCAN 512
struct env_buf {
	char data[ENV_SCAN];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct env_buf);
} env_scratch SEC(".maps");

/* env_has_ld_hijack reports whether the new process's environment carries a
 * dynamic-linker hijack variable — LD_PRELOAD, LD_AUDIT, or GLIBC_TUNABLES —
 * used to force a chosen .so (or tunable) into a legitimate program. It scans a
 * bounded window of the environment; env vars are NUL-separated, so a marker is
 * matched at the window start or right after a NUL. */
static __always_inline int env_has_ld_hijack(struct task_struct *task)
{
	__u64 start = BPF_CORE_READ(task, mm, env_start);
	__u64 end = BPF_CORE_READ(task, mm, env_end);
	if (!start || end <= start)
		return 0;

	__u64 span = end - start;
	__u32 n = span > ENV_SCAN ? ENV_SCAN : (__u32)span;
	if (n == 0)
		return 0;

	__u32 zero = 0;
	struct env_buf *b = bpf_map_lookup_elem(&env_scratch, &zero);
	if (!b)
		return 0;
	/* Read only the env span so the probe never faults past env_end, and scan
	 * only those bytes (break at n) so stale buffer tail is never matched. */
	if (bpf_probe_read_user(b->data, n, (void *)start) != 0)
		return 0;

	for (int i = 0; i < ENV_SCAN - 15; i++) {
		if (i >= (int)n)
			break;
		if (i != 0 && b->data[i - 1] != 0)
			continue;
		char c0 = b->data[i];
		if (c0 == 'L' && b->data[i + 1] == 'D' && b->data[i + 2] == '_') {
			if (b->data[i + 3] == 'P' && b->data[i + 4] == 'R' && b->data[i + 5] == 'E' &&
			    b->data[i + 6] == 'L' && b->data[i + 7] == 'O' && b->data[i + 8] == 'A' &&
			    b->data[i + 9] == 'D' && b->data[i + 10] == '=')
				return 1;
			if (b->data[i + 3] == 'A' && b->data[i + 4] == 'U' && b->data[i + 5] == 'D' &&
			    b->data[i + 6] == 'I' && b->data[i + 7] == 'T' && b->data[i + 8] == '=')
				return 1;
		}
		if (c0 == 'G' && b->data[i + 1] == 'L' && b->data[i + 2] == 'I' && b->data[i + 3] == 'B' &&
		    b->data[i + 4] == 'C' && b->data[i + 5] == '_' && b->data[i + 6] == 'T' &&
		    b->data[i + 7] == 'U' && b->data[i + 8] == 'N')
			return 1;
	}
	return 0;
}

/* fill_common captures the context every sensor shares. loginuid and the parent
 * comm are read here, in-kernel, so they cannot race a short-lived process. */
static __always_inline void fill_common(struct phage_event *e,
					struct task_struct *task, __u32 kind)
{
	__u64 id = bpf_get_current_pid_tgid();

	e->id = id;
	e->ts_ns = bpf_ktime_get_ns();
	e->kind = kind;
	e->pid = id >> 32;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->euid = 0;
	e->new_euid = 0;
	e->loginuid = BPF_CORE_READ(task, loginuid.val);
	e->cap_eff = 0;
	e->flags = 0;
	/* network fields default to zero; only on_tcp_connect fills them. */
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->dport = 0;
	e->family = 0;
	e->_pad2 = 0;
	/* path defaults to empty; only on_file_open fills it. The whole field must
	 * be zeroed: a ring-buffer slot is uninitialised memory, so leaving it would
	 * leak kernel stack bytes to userspace. */
	__builtin_memset(e->path, 0, sizeof(e->path));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	BPF_CORE_READ_STR_INTO(&e->pcomm, task, real_parent, comm);
}

/* commit_creds is the one chokepoint every privilege change passes through. */
SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new)
{
	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_CREDS_CHANGE);
	e->new_euid = BPF_CORE_READ(new, euid.val);
	/* kernel_cap_t became a single u64 `val` in Linux 6.3. */
	e->cap_eff = BPF_CORE_READ(new, cap_effective.val);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* sched_process_exec fires after a successful execve; current comm is already
 * the new image. We record it with its parent so userspace can judge whether
 * this parent->child execution is normal for the host. */
SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_sched_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_EXEC);
	/* mirror the current euid so the raise check still applies to setuid execs */
	e->new_euid = BPF_CORE_READ(task, cred, euid.val);
	/* Fileless execution: an executed image with no directory entry
	 * (i_nlink == 0) — a memfd or a deleted-then-run binary. Legitimate programs
	 * run from linked files, so nlink 0 is a sharp signal of in-memory execution
	 * that disk-based scanners miss, and it holds even if the attacker names the
	 * memfd after a trusted program. */
	if (BPF_CORE_READ(bprm, file, f_inode, __i_nlink) == 0)
		e->flags |= 1;
	/* Dynamic-linker hijack: launched with LD_PRELOAD / LD_AUDIT / GLIBC_TUNABLES
	 * in its environment — a chosen .so or tunable forced into the program. */
	if (env_has_ld_hijack(task))
		e->flags |= 2;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* tcp_connect is the single chokepoint for TCP active opens (both IPv4 and
 * IPv6 reach it once the destination is set). We read the destination before
 * reserving a ring-buffer slot so filtered connections cost nothing downstream;
 * loopback is dropped in-kernel to keep the hot path and the baseline clean. */
SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
	__u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family != AF_INET && family != AF_INET6)
		return 0;

	__u8 daddr[16] = {};
	if (family == AF_INET) {
		__be32 d = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		/* skc_daddr is network order; its first octet is the low byte. */
		if ((d & 0xff) == 127) /* 127.0.0.0/8 loopback */
			return 0;
		__builtin_memcpy(daddr, &d, sizeof(d));
	} else {
		BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	}
	__be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);

	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_CONNECT);
	__builtin_memcpy(e->daddr, daddr, sizeof(e->daddr));
	e->dport = bpf_ntohs(dport);
	e->family = family;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* has_prefix compares a compile-time-constant prefix against the start of the
 * resolved path. n is constant, so the loop fully unrolls to fixed-index loads
 * the verifier accepts without bounds tracking. */
static __always_inline int has_prefix(const char *s, const char *pfx, int n)
{
#pragma unroll
	for (int i = 0; i < n; i++)
		if (s[i] != pfx[i])
			return 0;
	return 1;
}

/* watched_path narrows the firehose of file opens to the directories where
 * persistence and credential tampering actually land. This is a *scoping*
 * filter — the kernel equivalent of choosing to hook tcp_connect for egress —
 * NOT a detection rule: whether a given program writing here is malicious is
 * decided later, by the learned baseline. Over-inclusion only means more for the
 * baseline to learn; the precise artifact class is assigned in userspace. */
static __always_inline int watched_path(const char *p)
{
	return has_prefix(p, "/etc/cron", 9) ||
	       has_prefix(p, "/var/spool/cron", 15) ||
	       has_prefix(p, "/etc/systemd/", 13) ||
	       has_prefix(p, "/run/systemd/system", 19) ||
	       has_prefix(p, "/etc/init.d/", 12) ||
	       has_prefix(p, "/etc/rc", 7) ||
	       has_prefix(p, "/etc/profile", 12) ||
	       has_prefix(p, "/etc/ld.so.", 11) ||
	       has_prefix(p, "/etc/passwd", 11) ||
	       has_prefix(p, "/etc/shadow", 11) ||
	       has_prefix(p, "/etc/sudoers", 12) ||
	       has_prefix(p, "/root/", 6) ||
	       has_prefix(p, "/home/", 6) ||
	       has_prefix(p, "/var/www/", 9) ||
	       has_prefix(p, "/srv/", 5) ||
	       has_prefix(p, "/usr/share/nginx/", 17) ||
	       has_prefix(p, "/usr/local/apache", 17) ||
	       has_prefix(p, "/var/lib/tomcat", 15);
}

/* security_file_open is the LSM chokepoint every file open passes through, and
 * it is on the kernel's allowlist for bpf_d_path(), which resolves the file's
 * full path. We gate on write intent (FMODE_WRITE) and on the path landing in a
 * watched tree, so ordinary reads and ordinary writes cost one path resolution
 * and nothing downstream. The resolved path is categorised in userspace; here we
 * only decide whether the event is worth emitting at all. */
SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	unsigned int mode = BPF_CORE_READ(file, f_mode);

	/* Honeytoken tripwire: any open (read OR write) of a planted decoy is
	 * reported. Gated on ht_armed so there is no per-open inode read unless
	 * honeytokens are actually in use. */
	__u32 z = 0;
	__u32 *armed = bpf_map_lookup_elem(&ht_armed, &z);
	if (armed && *armed) {
		__u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
		if (bpf_map_lookup_elem(&honeytokens, &ino)) {
			char hbuf[256];
			long hlen = bpf_d_path((struct path *)&file->f_path, hbuf, sizeof(hbuf));
			struct phage_event *e = reserve_event();
			if (e) {
				struct task_struct *t = bpf_get_current_task_btf();
				fill_common(e, t, PHAGE_EVT_HONEYTOKEN);
				if (hlen > 0)
					bpf_probe_read_kernel_str(&e->path, sizeof(e->path), hbuf);
				bpf_ringbuf_submit(e, 0);
			}
			return 0;
		}
	}

	if (!(mode & FMODE_WRITE))
		return 0;

	char buf[256];
	/* f_path is const in this kernel's BTF; bpf_d_path takes a mutable pointer.
	 * The cast only drops the qualifier — the CO-RE field offset still applies. */
	long len = bpf_d_path((struct path *)&file->f_path, buf, sizeof(buf));
	if (len < 0)
		return 0;
	if (!watched_path(buf))
		return 0;

	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_FILE);
	bpf_probe_read_kernel_str(&e->path, sizeof(e->path), buf);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* emit_enable records one high-risk kernel-enabling operation. These functions
 * are low-frequency, so a program with no history of them doing one stands out —
 * the setup phase of a kernel exploit or container escape, before escalation. */
static __always_inline int emit_enable(__u32 op)
{
	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	fill_common(e, task, PHAGE_EVT_ENABLE);
	e->flags = op;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* create_user_ns: an unprivileged user namespace — the common enabler of Linux
 * kernel LPE (it hands an unprivileged process capabilities inside the new ns,
 * widening the reachable kernel surface). */
SEC("fentry/create_user_ns")
int BPF_PROG(on_create_userns) { return emit_enable(PHAGE_ENABLE_USERNS); }

/* bpf_prog_load: loading an eBPF program — legitimate for a few tools, but also
 * how modern eBPF rootkits install themselves. */
SEC("fentry/bpf_prog_load")
int BPF_PROG(on_bpf_load) { return emit_enable(PHAGE_ENABLE_BPF); }

/* io_uring_setup and userfaultfd are recurring exploit primitives (heap
 * grooming, use-after-free timing). */
SEC("fentry/io_uring_setup")
int BPF_PROG(on_io_uring_setup) { return emit_enable(PHAGE_ENABLE_IOURING); }

SEC("fentry/new_userfaultfd")
int BPF_PROG(on_userfaultfd) { return emit_enable(PHAGE_ENABLE_UFFD); }

/* Self-defense: the agent watches its own sensory nerves. The dominant 2025
 * evasion is "blinding" — leaving the agent's process alive but killing or
 * unhooking its telemetry — so an attack on the monitor must itself be a signal.
 * The SENDER (current) is recorded; the target is known to be the agent. */

#define SIG_INT 2
#define SIG_QUIT 3
#define SIG_KILL 9
#define SIG_TERM 15
#define SIG_STOP 19

/* signal_generate fires for every signal delivered on the box; we return
 * immediately unless the target is the agent and the signal could kill/stop it.
 * Self-signals (the Go runtime uses SIGURG for preemption) are excluded both by
 * the lethal-signal filter and the sender==self check. */
SEC("tp_btf/signal_generate")
int BPF_PROG(on_signal_generate, int sig, void *info, struct task_struct *task,
	     int group, int result)
{
	__u32 self = phage_self_pid();
	if (!self)
		return 0;
	if (BPF_CORE_READ(task, tgid) != self)
		return 0;
	__u32 sender = bpf_get_current_pid_tgid() >> 32;
	if (sender == self)
		return 0; /* ignore the agent signalling itself */
	if (sig != SIG_INT && sig != SIG_QUIT && sig != SIG_KILL &&
	    sig != SIG_TERM && sig != SIG_STOP)
		return 0;

	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *cur = bpf_get_current_task_btf();
	fill_common(e, cur, PHAGE_EVT_SELFDEF);
	e->flags = PHAGE_SELFDEF_SIGNAL;
	e->new_euid = sig; /* selfdef carries the signal number here */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ptrace_attach: someone attaching a debugger to the agent (code injection /
 * inspection). Near-zero baseline — the agent is never a legitimate ptrace
 * target. */
SEC("fentry/ptrace_attach")
int BPF_PROG(on_ptrace_attach, struct task_struct *task)
{
	__u32 self = phage_self_pid();
	if (!self)
		return 0;
	if (BPF_CORE_READ(task, tgid) != self)
		return 0;
	__u32 sender = bpf_get_current_pid_tgid() >> 32;
	if (sender == self)
		return 0;

	struct phage_event *e = reserve_event();
	if (!e)
		return 0;
	struct task_struct *cur = bpf_get_current_task_btf();
	fill_common(e, cur, PHAGE_EVT_SELFDEF);
	e->flags = PHAGE_SELFDEF_PTRACE;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
