# Roadmap

Direction, not dates. Each milestone ships something usable and demonstrable.

## M0 — Scaffolding ✅
Architecture, pipeline seams, docs, buildable Go skeleton. (You are here.)

## M1 — Privilege-escalation detection (learn + alert)
The first real value.
- [x] `creds.bpf.c` hooking `commit_creds` — compiles with CO-RE and passes the
      kernel verifier on the target (Ubuntu 26.04, kernel 7.0, x86_64).
- [x] Stream events to userspace: sensor loader (`cilium/ebpf`) + ring-buffer
      reader + decode. Verified live on the test server — real credential
      transitions captured end to end (pid, comm, uid/euid, caps).
- [x] Measure transition *direction*: a non-root process raising to root vs
      root dropping privileges. Direction is a feature, not a rule.
- [x] Enrichment: process lineage + session provenance (audit loginuid, tty).
      Live-verified — the same setuid escalation is told apart by provenance:
      spawned by systemd with no login session vs run inside an admin login.
- [x] Baseline persistence: atomic JSON snapshot behind a pluggable
      `store.Repository` seam (embedded KV can drop in later).
- [x] Learn mode end-to-end; alert mode scoring with explained verdicts and the
      policy engine choosing the response.
- [x] Deterministic pipeline tests: decode layout contract + scorer behaviour
      (attack scores high with reason, normal scores low, empty baseline neutral).
- **Demo — done.** A real HTTP attack from a remote machine exploited a lab web
  app (command injection) to run as `webapp`, then escalated to root via a
  setuid binary. Phage flagged the escalation **CRITICAL (score 0.83)** with the
  reason "raised to root with no login session behind it (never seen on this
  host)", while legitimate raises inside a login session stayed silent. See
  [docs/demo/external-escalation.md](demo/external-escalation.md).

## M2 — Enforcement (contain)
- [x] Reversible containment: cgroup-v2 freeze of the offending process tree.
      Live-verified — the same remote attack, in `enforce` mode, was frozen
      mid-run (`cgroup.freeze=1`, euid 0 but unable to execute), not killed.
- [x] Audit log (append-only JSON lines) with the triggering reason per action.
- [x] `phage` CLI over a Unix control socket: `status`, `events [n]`, and
      `thaw <pid>` to release a false positive. Verified live against the attack.
- [x] Race-free provenance: loginuid is now read in-kernel (eBPF), not from /proc.
- [x] Threshold tuning via a YAML config file (`-config`), overlaid on defaults
      and validated (notify ≤ contain, both in [0,1]); path flags override the
      file, `-mode` may only lower it, and no flag can enable a host-modifying
      feature. Unit-tested, including that the committed example always loads.

## M2.5 — Exec sensor + containment safety
- [x] Second eBPF sensor: `sched_process_exec` — catches the universal effect of
      RCE (a service spawning a never-before-seen program) as a parent→child
      pair anomaly. One object, shared ring buffer, both programs attached.
- [x] Containment guardrails (`containmentSafe`): never freeze an interactive
      login session, never freeze the control plane (sshd/systemd/…/phaged), and
      only ever freeze an actual privilege escalation — after a live enforce run
      froze SSH logins and locked the test box out. See docs/concepts/modes.md.
- See [threats-and-behavioral-defense](concepts/threats-and-behavioral-defense.md)
  for the exploit-class → host-effect mapping this sensor set is built against.

## M2.6 — Egress sensor (reverse shells + C2)
- [x] Third eBPF sensor: `tcp_connect` (fentry) — catches the universal effect of
      a foothold phoning home (a program with no egress history dialing out) as a
      novel `program`/`program→port` anomaly. Same object, same ring buffer;
      loopback dropped in-kernel, destination kept for the audit trail but not
      learned (IPs are too high-cardinality). Unit-tested (decode layout + IPv4/
      IPv6 destination + extractor keying).
- [x] Live-verified on the test box (kernel 7.0): the sensor loads and all three
      programs pass the verifier; a service-spawned `bash` dialing out was flagged
      **CRITICAL (0.84)** while a normal `curl` to :443 stayed silent. See
      [demo/egress-detection](demo/egress-detection.md).
- See [egress-detection](concepts/egress-detection.md) for the design and gaps.

## M2.7 — File/persistence sensor (webshells, keys, cron)
- [x] Fourth eBPF sensor: `security_file_open` (fentry) with `bpf_d_path` path
      resolution — catches the universal effect of an intruder establishing
      persistence (a program writing a persistence/credential artifact class it
      has never written on this host) as a novel `program→class` anomaly. Same
      object, same ring buffer. Write-opens in watched trees only (a scoping
      filter, not a rule); the path is resolved in-kernel and the coarse artifact
      class assigned in userspace. Unit-tested (272-byte layout + path
      categorisation + extractor keying).
- [x] Live-verified on the test box (kernel 7.0): all four programs pass the
      verifier; a service-spawned `bash` appending to `authorized_keys` was
      flagged **CRITICAL (0.83)** and dropping a webshell **ALERT (0.57)** — lower
      because this host legitimately writes PHP, so only the novel *writer* stood
      out — while a legit `cp` deploy of a `.php` stayed silent. See
      [demo/file-persistence](demo/file-persistence.md).
- See [file-persistence-detection](concepts/file-persistence-detection.md) for
  the design and gaps.

## Advanced-evasion coverage (crosscutting)
Techniques that defeat file-based tooling, caught behaviourally.
- [x] **Fileless / in-memory execution.** The exec sensor flags a program run
      from an anonymous `memfd` or an unlinked binary — the executed image has no
      on-disk link (`i_nlink == 0`). Near-zero false positive, so it weighs
      heaviest; holds even when the memfd is named after a trusted program.
      Live-verified: a payload run from memory flagged CRITICAL (0.87) while
      on-disk execs stayed silent. See [demo](demo/fileless-execution.md).
- [x] **Enabling syscalls** (signal #5) — `fentry` on `create_user_ns`,
      `bpf_prog_load`, `io_uring_setup`, `new_userfaultfd`. Catches the setup an
      exploit does *before* it escalates, as a program performing an enabling op
      it has no history of. Live-verified: a session-less service creating a user
      namespace flagged while a known admin tool doing the same stayed silent.
      See [demo](demo/kernel-enabling-ops.md).
- [x] **Dynamic-linker hijack.** The exec sensor scans a bounded window of the
      new process's environment in-kernel and flags `LD_PRELOAD` / `LD_AUDIT` /
      `GLIBC_TUNABLES`. Scored as a red-flag override (floors the verdict when
      novel, so it is undiluted and caught even when the program/parent look
      normal). Live-verified: a service launched with `LD_PRELOAD` flagged
      CRITICAL while the same program without it stayed silent. See
      [demo](demo/dynamic-linker-hijack.md).

## Self-defense / anti-blinding (crosscutting)
- [x] The agent watches attacks on **itself**: `tp_btf/signal_generate` (a lethal/
      stop signal to the agent from a non-supervisor) and `fentry/ptrace_attach`
      (a debugger/injector attaching to it), pid-aware via a `self_pid` map.
      Scored outside the learned baseline (tampering with the monitor is
      intrinsically critical), plus a dead-man's-switch that flags a previously-
      active event stream going silent. Live-verified: a ptrace attach flagged
      CRITICAL while the agent kept running. See
      [demo](demo/agent-self-defense.md).
- [x] **Tamper-resistance (enforcement):** `enforcement.self_protect` (was `-protect`) loads a separate
      eBPF-LSM object (`selfprotect.bpf.o`, `lsm/task_kill`) that *denies* a
      lethal/stop signal aimed at the agent from anyone but pid 1 or itself
      (the launcher only with `dev.trust_launcher_signals`) — so an attacker (even root) cannot kill it to blind it, while
      `systemctl stop`/reboot always work. Opt-in; inert without BPF LSM.
      Live-verified: a root `kill -9` on the agent was refused (EPERM), the agent
      survived, the launcher stopped it cleanly. See
      [demo](demo/tamper-resistance.md).
- [ ] Round out tamper-resistance: write-protect the agent's binary/maps/audit
      log (`lsm/file_open`/`bpf()` guards) and a watchdog restart. Ceiling stays a
      ring-0 attacker.

## Scoring: novelty, not rarity (crosscutting)
- [x] `baseline.Surprise` now measures whether a value is *established* on the
      host, not its probability share of all events. The old `1 - count/total`
      branded even frequently-seen high-cardinality values (exec pairs, ports) as
      surprising, drowning the real signal; the egress demo surfaced this live.
      Fixed and regression-tested (`TestSurpriseIsNoveltyNotRarity`); the same
      attack against the same baseline then produced exactly one alert.

## M3 — Blast-radius containment (auto-jail)
- [x] Learn a service's syscall behaviour: a `tp_btf/sys_enter` eBPF profiler
      (`bpf/programs/jail.bpf.c`) gated on one cgroup, counting syscalls into a
      map. Its own object, loaded only by `phage-jail`, never by the daemon.
- [x] Generate a least-privilege seccomp profile (OCI JSON + systemd drop-in)
      from the learned set, default `ERRNO(EPERM)`, with a minimal always-allow
      baseline. Arch syscall table generated from the kernel header. Pure-Go
      generation, unit-tested (`internal/jail/{syscalls,profile,seccomp}`).
- [x] Live-verified (kernel 7.0): profiled a web service from its first
      instruction (52 syscalls), generated its profile, and proved enforcement —
      jailed, the service's interpreter is denied `unshare`/`ptrace` (EPERM)
      while still running. See [demo/auto-jail](demo/auto-jail.md) and
      [ADR 0003](architecture/decisions/0003-auto-jail-seccomp.md).
- [x] **eBPF-LSM exec-lock** (`bpf/programs/jail_lsm.bpf.c`,
      `lsm/bprm_check_security`): deny any new `execve` inside a locked service's
      cgroup — the gap seccomp cannot cover (a service's own post-startup exec).
      Default-allow, scoped to the cgroups you lock, lifted on tool exit.
      Live-verified (kernel 7.0, booted `lsm=...,bpf`): a process in the locked
      cgroup is denied exec (EPERM) while the service keeps serving and other
      cgroups are untouched. `phage-jail lock`. See
      [demo/auto-jail](demo/auto-jail.md).
- [x] **Allowlist exec-lock** (learn→enforce): `phage-jail lock -learn N` records
      the programs a service legitimately execs, then permits only those and
      denies anything new. Keyed on the executable path (not inode — coreutils is
      one multi-call binary, so an inode key would let "allow date" allow id too).
      Live-verified: a learned `/bin/date` stays allowed while `bash` and `id` are
      denied, and the service keeps running.
- [ ] Apply the seccomp profile automatically (write the drop-in, restart jailed)
      with the learn→enforce ladder and a staging-validation gate.
- [ ] Extend LSM enforcement to egress/file per cgroup, reusing the detection
      baseline.

## M4 — Self-healing
- [x] **Network quarantine (isolate):** an egress/C2 verdict in enforce severs the
      offending service's outbound network (`cgroup/connect` programs on its
      cgroup) without killing it — C2 dies, the process lives for forensics,
      reversible via `phage thaw`. Live-verified: a beacon's first dial connected
      (and was detected), every subsequent dial was blocked, the process never
      stopped. See [demo](demo/network-quarantine.md).
- [ ] Also cut established sockets (`cgroup_skb/egress`); TTL auto-release.
- [x] **Self-heal:** `enforcement.self_heal` (was `-heal`) snapshots sentinel files (authorized_keys,
      cron, ld.so.preload) and, on a malicious-write verdict (enforce), atomically
      restores the known-good version while quarantining the attacker's as
      evidence. Verdict- and snapshot-gated, so a legitimate edit is never
      reverted. Live-verified: a backdoor key appended to authorized_keys was
      removed within a moment, the legit key kept, the attacker version saved. See
      [demo](demo/self-healing.md).
- [ ] Re-snapshot on verified/session writes; extend to the web root; recovery to
      a broader known-good state.

## Model evolution (crosscutting)
Frequency surprise → co-occurrence → time decay → sequence/graph models, all
behind the fixed `scorer.Scorer` seam. See
[design/analysis-engine](design/analysis-engine.md).

## Backlog — next push (parked)
Prioritized from early community feedback and a gap review; parked for the next
work session.

**Trust the baseline (early-stage gaps)**
- [ ] Seed/import a baseline from a known-clean image or host, so a fresh install
      doesn't have to assume the box is clean during the learning window.
- [ ] Maintenance mode + baseline-drift handling: a toggle to relearn/suppress
      during a deploy or package upgrade, so a new binary spawning new children
      (legitimate drift) isn't treated as an intrusion in enforce.
- [ ] Per-cgroup / per-service baseline models (service-scoped "normal").

**New detectors**
- [ ] Listening-port sensor: a service that suddenly opens a listening socket it
      never has (hook bind/listen), complementing the outbound-egress sensor.
- [ ] Explicit "executed from a world-writable path" signal (`/tmp`, `/dev/shm`),
      rather than relying on exec-pair novelty alone.
- [ ] Strengthen new-systemd-unit detection (alongside the existing cron watch).

**Response maturity (past freeze/isolate → proactive)**
- [ ] Auto-apply least-privilege seccomp — finish auto-jail: write the drop-in,
      restart jailed, learn→enforce with a staging gate.
- [ ] Recovery beyond freeze/isolate: broader known-good restoration (self-heal).

**Evidence**
- [ ] Reproducible red-team benchmarks, including low-and-slow evasion, published
      and compared against Falco / Tetragon / Tracee.

**Reach & hardening**
- [ ] Broaden container / namespace sensors.
- [ ] Harden signed-eBPF self-protection.

## Later
Tamper-resistance, signed eBPF, multi-host aggregation, a fleet view.
