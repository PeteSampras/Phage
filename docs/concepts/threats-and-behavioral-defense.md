# Threats and behavioral defense

Phage is a **host-based** Linux agent. It sees syscalls — process execution,
network, file I/O, credential changes — not application payloads. So it does not
chase CVEs; it watches for the **behavioral effect** an exploit produces on the
host, learned against the host's own baseline. That is what lets it catch a bug
it has never heard of.

For each class below: how it's exploited, what the host can actually observe,
and — honestly — where a host agent is blind.

## 1. PHP application RCE
**Exploited via:** command injection into `system`/`exec`/`shell_exec`/backticks;
unsafe `unserialize()` → object injection + POP gadget chains; file upload →
webshell; LFI/RFI (log poisoning, `php://filter`).
**Host-observable (strong):** the interpreter becomes the parent of a shell —
`php-fpm → sh/bash/curl/wget/nc` (MITRE T1505.003); a web-user process writing a
`.php`/`.phtml` under the web root (webshell drop) or modifying an existing one;
outbound `connect` from the interpreter.
**Blind spot:** the object-injection/POP mechanism is in-process PHP memory — no
syscall until a gadget reaches an exec/file/network sink.

## 2. Node.js RCE
**Exploited via:** command injection through `child_process` with `shell:true`;
**prototype pollution → RCE** (poison `Object.prototype`, hit a "universal
gadget"; USENIX Security 2023 "Silent Spring"); unsafe deserialization;
vulnerable dependencies.
**Host-observable (strong, same shape as PHP):** `node → sh/bash`, or `node`
spawning `curl`/`python`/`nc`; sometimes an injected `NODE_OPTIONS=--require=…`
or odd `argv0` in the child's `execve`; webshell writes and outbound connections.
**Blind spot:** the pollution itself (`obj.__proto__.x = y`) emits no syscall —
only its consequence, when a polluted value flows into exec/fs/socket, is visible.

## 3. Linux userspace privilege escalation
**Exploited via:** SUID abuse, sudo misconfig (`env_keep += LD_PRELOAD`),
GTFOBins (`find`/`vim`/`tar`/`python` → shell), capability abuse
(`cap_setuid`, `cap_sys_admin`). Current: sudo CVE-2025-32463 (`--chroot`,
loads a malicious NSS lib as root; CISA KEV) / CVE-2025-32462 (`--host`).
**Host-observable (strong):** effective uid dropping to 0 via setuid from a
non-login/service context (MITRE T1548.001/003); a GTFOBins binary spawning a
shell; `LD_PRELOAD` pointing at a writable path in `execve` envp.
**Blind spot:** telling malicious from legitimate privilege use is context, not a
single syscall (legit `passwd`/`su`/`sudo` exist) — which is exactly why Phage
leans on provenance (is there a login session?) and a learned baseline.

## 4. Linux kernel privilege escalation
**Exploited via:** memory-corruption bugs reachable from userland — e.g.
nf_tables UAF/double-free (CVE-2024-1086, CISA KEV), io_uring UAF — then
heap-spray/grooming (`msg_msg`, pipe buffers, io_uring rings) to overwrite a
cred/page structure. Unprivileged user namespaces (`unshare(CLONE_NEWUSER)`) are
a common enabler.
**Host-observable (partial):** enabling syscalls from an unexpected process
(`unshare` new-userns, `io_uring_setup`, `bpf()`, `userfaultfd`, nftables
object creation); the **outcome** — `commit_creds` to uid 0 with no preceding
SUID/sudo `execve`.
**Blind spot — the hardest class:** the corruption happens inside kernel memory
and emits no syscall. Detection is indirect: anomalous enabling syscalls + an
unexplained credential elevation. Treat as "detect the blast radius," not "detect
the bug."

## 5. SQL injection
**Exploited via:** in-band / blind for data; and the subset that reaches the OS —
MySQL `INTO OUTFILE` / UDF, MSSQL `xp_cmdshell`, PostgreSQL `COPY … PROGRAM`.
**Host-observable (only when it crosses into the OS):** the DB daemon becomes the
parent of a shell (`postgres → sh`, `sqlservr → cmd`); the DB process writing a
file outside its data dir (web-root `.php`, a `.so`); outbound connect from the
DB daemon.
**Blind spot — important:** raw SQLi payload content is invisible at the syscall
layer. In-band/blind SQLi that only reads data through the normal response path
produces **no host signal**. Phage claims only *SQLi-to-OS-exec/file-write*, not
SQLi detection in general.

## 6. Cross-site scripting (XSS)
**Exploited via:** stored / reflected / DOM — script runs in the **victim's
browser** in the origin's context.
**Host-observable:** essentially **none on the server**. The payload executes on
a different machine; the server only does its ordinary store/serve syscalls.
**Out of scope — stated plainly:** XSS needs browser/client instrumentation, CSP
reporting, or a WAF/RASP. A host syscall tracer cannot see it, and Phage does not
claim to.

## The signals Phage watches (broadest coverage)
Ranked by how many of the above effects they catch. Classes 1, 2, 3, 4, the OS
subset of 5, and the *outcome* of the kernel class are covered; 6 is
intentionally not.

| # | Signal | Status in Phage |
|---|--------|-----------------|
| 1 | A long-lived service spawns a never-seen program (shell/utility) — parent→child pair anomaly | ✅ exec sensor (`sched_process_exec`) |
| 1b | **Fileless / in-memory execution** — a program run from an anonymous `memfd` or an unlinked binary (`i_nlink == 0`), invisible to disk scanners | ✅ exec sensor (`FeatExecFileless`) — live-verified. See [demo](../demo/fileless-execution.md) |
| 1c | **Dynamic-linker hijack** — a program launched with `LD_PRELOAD` / `LD_AUDIT` / `GLIBC_TUNABLES` in its environment | ✅ exec sensor (`FeatExecLdPreload`, in-kernel env scan) — live-verified. See [demo](../demo/dynamic-linker-hijack.md) |
| 2 | An unprivileged process reaches root with **no login session** behind it | ✅ privilege sensor (`commit_creds`) + provenance |
| 3 | Outbound connection from a process that normally never egresses | ✅ egress sensor (`tcp_connect`) — live-verified. See [egress-detection](egress-detection.md) and the [demo](../demo/egress-detection.md) |
| 4 | Writes to persistence/credential artifacts (`authorized_keys`, `/etc/cron*`, web-root `*.php`, `ld.so.preload`) | ✅ file sensor (`security_file_open` + `bpf_d_path`) — live-verified. See [file-persistence-detection](file-persistence-detection.md) and the [demo](../demo/file-persistence.md) |
| 5 | Dangerous enabling syscalls (`unshare` userns, `bpf` load, `io_uring_setup`, `userfaultfd`) from a process with no history of them | ✅ enable sensors (`fentry` on `create_user_ns`/`bpf_prog_load`/`io_uring_setup`/`new_userfaultfd`) — live-verified. See [demo](../demo/kernel-enabling-ops.md) |
| 6 | **Tamper with the monitor itself** — kill/stop/ptrace the agent or blind its telemetry | ✅ **detect**: `signal_generate` + `ptrace_attach` + dead-man's-switch; **prevent** (`enforcement.self_protect` in mode enforce): `lsm/task_kill` denies killing the agent even as root ([tamper-resistance demo](../demo/tamper-resistance.md)). Live-verified. Ceiling: a ring-0 attacker |

Every signal is judged against the host's **learned baseline**, never a fixed
rule — so "normal for this host" is what decides, and a never-before-seen
combination is what stands out.

## References
MITRE [T1505.003](https://attack.mitre.org/techniques/T1505/003/),
[T1548](https://attack.mitre.org/techniques/T1548/); USENIX Security 2023
"Silent Spring" (prototype pollution → RCE in Node.js); sudo
[CVE-2025-32463 / CVE-2025-32462](https://www.helpnetsecurity.com/2025/07/01/sudo-local-privilege-escalation-vulnerabilities-fixed-cve-2025-32462-cve-2025-32463/);
nf_tables [CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086);
NetSPI [SQLi OS-command techniques](https://sqlwiki.netspi.com/attackQueries/executingOSCommands);
reference implementations of this model: Falco (alerting) and Tetragon (in-kernel
enforcement).
