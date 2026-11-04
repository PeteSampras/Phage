<div align="center">

# Phage

**An autonomous immune system for Linux servers — it contains what it can't yet patch.**

*A phage is a biological agent that hunts down invaders and neutralizes them — a
living defense that works without knowing the pathogen in advance. This one does
the same for your server.*

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/AzozzALFiras/Phage)](go.mod)
[![Go Report Card](https://goreportcard.com/badge/github.com/AzozzALFiras/Phage)](https://goreportcard.com/report/github.com/AzozzALFiras/Phage)
![Platform: Linux eBPF](https://img.shields.io/badge/platform-Linux%20eBPF-blue)

**Free and open source** · single static binary · no agent fleet, no Kubernetes

</div>

---

New vulnerabilities never stop appearing — in PHP, in Node.js, in the kernel
itself, and in things not written yet. Chasing a patch for each one is a race you
lose by design. Phage takes the other path: **assume the breach**, then make it
survivable.

Phage is a lightweight eBPF agent that learns how a server *normally* behaves,
then detects and contains anything that steps outside it — **without a signature
for the specific vulnerability**. The heavy lifting runs in the kernel, so it
stays cheap; the userspace agent ships as a single static binary.

## Contents

- [Seeing it work](#seeing-it-work-a-real-attack-stopped)
- [The thesis](#the-thesis)
- [How it detects](#how-it-detects) — the learned baseline, in detail
- [How it responds](#how-it-responds) — the graduated-response matrix
- [Safety](#safety-the-ladder-and-what-enforce-will-never-touch)
- [How it's built](#how-its-built) — architecture, inline
- [Install](#install) · [Running it](#running-it) · [Build from source](#build-from-source)
- [Honest limitations](#honest-limitations)
- [Status](#status) · [Contributing & security](#contributing--security) · [License](#license)

## Seeing it work: a real attack, stopped

On a test server, a remote machine exploited a vulnerable web app (command
injection) to run as the unprivileged `webapp` user, then escalated to root via a
setuid binary. In `enforce` mode Phage caught and froze the escalation the instant
it happened — no signature for the bug, the payload, or the binary:

```
CRITICAL score=0.83 action=freeze pid=6518 comm="rootshell" uid=999->euid=0 ::
    an unprivileged process raised itself to root;
    raised to root with no login session behind it (never seen on this host)
CONTAIN pid=6518 FROZEN (process tree quarantined, reversible)
```

Legitimate privilege use inside an SSH login stayed silent — because on this host
root is only ever reached *through a login session*, and this wasn't one. Phage
didn't recognize the exploit; it recognized that the result was impossible for
this server.

> Evidence and reproduction: four attacks run with Phage off (they succeed) and on
> (detected / contained / blocked) in [docs/demo/proof-before-after.md](docs/demo/proof-before-after.md);
> detection-rate *and* false-positives measured together in [PhageBench](docs/benchmark/phagebench.md).

## The thesis

1. **Shrink the attack surface.** Fewer doors, fewer ways in.
2. **Contain the blast radius.** An exploited service still can't do more than it
   normally does.
3. **Detect by behavior, not signatures.** Catch the *effect* of an exploit (an
   impossible path to root, a service spawning a shell), not a fingerprint.
4. **Respond and recover on its own** — freeze, isolate, roll back.

The first three need no prior knowledge of the vulnerability. That is the point:
a signature can only catch an attack someone has already seen and described;
behavior catches the *consequence*, which an attacker cannot avoid producing.

## How it detects

Phage never ships a list of "bad" things. Instead, every interesting kernel event
flows through a four-stage pipeline, and the host's own history decides what is
normal:

```
kernel event  ──►  feature  ──►  baseline  ──►  score + reasons  ──►  verdict
 (eBPF sensor)    (measure it)  (seen before?)  (how surprising?)   (what to do)
```

1. **Measure, don't match.** A sensor turns each event into a few plain features —
   e.g. *"this process reached euid 0"*, *"there was no login session behind it"*,
   *"this parent has never spawned this child before"*. No feature says "bad"; it
   just describes what happened.
2. **Compare to the learned baseline.** In `learn` mode Phage records these
   features per host and builds a statistical picture of normal. Scoring is based
   on **novelty**, not rarity: a value the host has genuinely never produced is
   surprising; a value it produces all day is not — even if there are thousands of
   distinct ones.
3. **Score with confidence gating.** A feature Phage has barely observed counts for
   little, so a freshly-deployed agent off a thin baseline does not raise confident
   alerts. Weak signals are averaged; a handful of **red-flag features** that mean
   malice on their own (fileless execution, an `LD_PRELOAD` hijack, a root
   escalation with no session) instead *floor* the score high — so an attacker who
   disguises everything else as normal is still caught.
4. **Explain the verdict.** Every score carries human-readable reasons ("raised to
   root with no login session behind it (never seen on this host)"), so an operator
   can always see *why* — there is no opaque model to trust.

The signals Phage watches today, each scored this way:

| Signal | Catches | Status |
|---|---|---|
| A process reaches **root with no login session** behind it | Linux/kernel privesc, SQLi/RCE → root | ✅ |
| A service spawns a **never-before-seen program** (parent→child), incl. **fileless** in-memory execution and **LD_PRELOAD** hijacks | PHP/Node RCE, command injection, webshells, reverse shells, memfd malware, linker injection | ✅ |
| **Outbound connection from a process that never egresses** | reverse shells, C2, exfil | ✅ |
| **Writes to persistence/credential files** (web-root `.php`, `authorized_keys`, cron) | webshell drop, backdoored keys, persistence | ✅ |
| **High-risk kernel-enabling ops** by a process with no history of them (userns, eBPF load, io_uring, userfaultfd) | kernel-exploit setup, container escape, eBPF rootkits | ✅ |
| **Tamper with the agent itself** — kill/stop/ptrace it, or telemetry going silent | EDR blinding / anti-detection | ✅ |
| **A process reads a planted decoy** (honeytoken) credential file | credential theft, intruder snooping | ✅ |

<sub>✅ verified live against a real attack on a test server. Each row links to a full write-up from the [docs index](docs/README.md#demos--live-verified-against-real-attacks).</sub>

**What it cannot see, stated plainly:** XSS runs in the victim's browser and
raw SQL-injection payloads live inside the DB query — neither is host-observable,
so Phage cannot see the payload. What it *can* see is the moment that exploit
reaches the operating system: the shell it spawns, the root it gains, the
connection it opens. It defends the server by catching effects, not payloads.

## How it responds

In `enforce` mode Phage doesn't just kill — killing destroys the evidence and
tips the attacker off. A **graduated-response matrix** picks the least-invasive
action that is *enough* for what the process actually did, and climbs only if the
process keeps earning it:

| Rung | What it does | Mechanism | Chosen for |
|---|---|---|---|
| **notify** | alert + append to the audit trail, nothing else | — | lower-confidence or easily-inspected signals |
| **isolate** | sever the process's outbound network, keep it running | an eBPF `cgroup/connect` hook on its cgroup denies new egress | a reverse shell / C2 beacon — the channel dies, forensics survive |
| **freeze** | pause the whole process tree, reversibly | moved into a cgroup-v2 freezer | a near-certain intruder (honeytoken read, no-session root) |

Two properties make this safe to leave on:

- **Escalation only moves up.** A process already contained at one rung isn't
  re-actuated or re-logged for a weaker verdict; a *stronger* verdict promotes it.
  In a live run one process dialed out (→ **isolate**) and then read a credential
  decoy (→ **freeze**) — the same pid climbed the ladder as the evidence mounted.
- **Containment is a lease, not a life sentence.** An isolated process that goes
  quiet is **released automatically** (it kept running and stopped misbehaving —
  that's real evidence it was benign or transient). A **frozen** process is
  *held* for a human (`phage thaw`), never auto-released: a frozen process is
  silent by construction, so "quiet" proves nothing, and freeze is reserved for
  near-certain verdicts.

Phage also **self-heals**: a malicious write to a watched file (`authorized_keys`,
cron, `ld.so.preload`) is rolled back to the known-good version within
milliseconds, and the attacker's version is kept in quarantine as evidence.

> Full runs with raw logs: [graduated-response](docs/demo/graduated-response.md),
> [network-quarantine](docs/demo/network-quarantine.md),
> [self-healing](docs/demo/self-healing.md).

## Safety: the ladder, and what enforce will never touch

A security tool that can lock you out of your own server is worse than none. Two
guarantees prevent that:

- **Phage never jumps to enforcement.** Every deployment climbs the ladder:
  `learn` (watch and build the baseline, act on nothing) → `alert` (score and
  warn, still act on nothing) → `enforce` (contain). An immature baseline
  therefore *cannot* act, and an empty one is neutral by construction.
- **Containment has hard guardrails** — born from a real lockout during
  development, where an early build froze `sshd` and shut the door on itself.
  Enforce mode will **never freeze an interactive login session or the control
  plane** (`sshd`, `systemd`, `phaged`, …), whatever the score. An attacker
  operating *as* the control plane is deliberately out of scope for automatic
  containment — availability wins that trade.

The `phage` CLI (`status`, `events`, `thaw <pid>`) gives an operator a live view
and a manual override at all times.

## How it's built

Phage is one Go binary and a set of small eBPF programs — no kernel module, no
agent fleet, no Kubernetes:

- **Kernel side (C / eBPF CO-RE).** A handful of programs attached to the events
  that matter — `commit_creds` (privilege changes), `sched_process_exec` (exec),
  `tcp_connect` (egress), `security_file_open` (writes + honeytokens), plus
  kernel-enabling hooks and LSM hooks for self-defense. They do the hot-path
  filtering in-kernel and push only the few events worth analysing up a single
  shared ring buffer. CO-RE + BTF means one compiled object runs across kernels
  without recompilation.
- **Userspace side (Go, `cilium/ebpf`).** A cgo-free, statically-linked daemon
  (`phaged`) loads the sensors and runs the pipeline: **sensor → enrich →
  analysis → policy → response**, one package per stage. `enrich` adds process
  lineage and session context; `analysis` is the feature/baseline/score/verdict
  engine above; `policy` is the response matrix; `response` actuates (freeze,
  isolate, self-heal) — all reversible.
- **Operations.** An append-only JSON audit trail records every verdict and
  action; the `phage` CLI talks to the daemon over a local Unix socket.

Because detection is a pluggable `Scorer` and detectors are just *features* over a
baseline, adding a new detector means adding a measurement — never an `if parent
== "bash"` rule. The design decisions behind this (why Go + eBPF, why behavioral,
why seccomp for jails) are recorded as ADRs under
[docs/architecture/decisions](docs/architecture/decisions/).

## Install

**This fork is built in-house from a pinned commit; it never downloads release
artifacts.** The upstream `curl | sudo bash` installer (which fetched
`releases/latest` unpinned) has been removed — see [FORK.md](FORK.md). Build on
a Linux host from a reviewed commit and install what you built:

```sh
git clone https://github.com/PeteSampras/phage.git && cd phage
git checkout <reviewed-commit-sha>   # pin: never build an unreviewed tip
make gen-vmlinux bpf build            # needs Go, clang/llvm and libbpf headers
sudo make install                     # starts nothing; see below
sudo systemctl daemon-reload && sudo systemctl enable --now phage
```

It lays the pieces out like this:

| Path | What |
|---|---|
| `/usr/local/bin/{phaged,phage,phage-jail}` | the daemon, the operator CLI, the jail tool (`phage-jail` is **not** gated by the config file — do not install it on a canary; see [FORK.md](FORK.md)) |
| `/usr/local/lib/phage/*.bpf.o` | the compiled eBPF sensors |
| `/etc/phage/phage.yaml` | configuration (ships as `mode: learn`, every enforcement and deception feature off) |
| `/etc/systemd/system/phage.service` | the systemd unit |
| `/var/lib/phage/` | the learned baseline and the audit trail |

Requires Linux with kernel BTF (`/sys/kernel/btf/vmlinux`); runs as root because
it loads eBPF and drives the cgroup freezer.

## Running it

*The learn → alert → enforce ladder.* Phage is meant to run as a systemd service
and to earn trust one rung at a time — the ladder is the safety mechanism, so
never skip it:

```sh
systemctl status phage      # is it running?
journalctl -u phage -f      # watch it, live
phage status                # mode, uptime, events, alerts, contained
phage events                # the recent verdicts, each with its reasons
phage thaw <pid>            # manually release a contained process
```

1. **Learn** *(days, not minutes — the default)* — builds a per-host baseline and
   does nothing else. Give it long enough to see your normal: weekly cron,
   deploys, backups.
2. **Alert** — when the baseline is mature, set `mode: alert` in
   `/etc/phage/phage.yaml` and `systemctl restart phage`. Now it scores and warns
   but still never acts; this is where you confirm it's quiet on a normal day.
3. **Enforce** — only then set `mode: enforce` **and** switch on, one by one,
   the acting features you want in the `enforcement:` block of
   `/etc/phage/phage.yaml`. Now it contains, proportionally and reversibly (see
   [How it responds](#how-it-responds)), with the guardrails that it will never
   freeze your SSH session or the control plane.

**In this fork nothing acts by default, even in enforce mode.** Every acting
feature — `isolate` (network quarantine), `freeze`, `self_heal` and
`self_protect` (eBPF-LSM tamper-resistance) — is off until its own key is set to
the literal `true` in the config file, and is honoured only with
`mode: enforce`; phaged refuses to start if one is set in learn or alert mode.
Decoys (`deception.honeytokens`) are a separate opt-in allowed in alert and
enforce. Every start writes a `startup` audit record (mode, what armed, the
config file's path and sha256, version); when anything arms phaged also logs one
`ENFORCEMENT ARMED` line and writes an `enforcement_armed` record. See
[FORK.md](FORK.md).

```yaml
mode: enforce
audit_path: /var/lib/phage/audit.jsonl   # required for any of the below
enforcement:
  isolate: true        # sever egress of a process on a high egress/C2 verdict
  freeze: false
  self_heal: true
  self_protect: false
deception:
  honeytokens: true
```

**No command-line flag can enable any of these.** The old `-heal`, `-protect`
and `-honeytokens` flags are now errors naming the config key that replaced
them. `-mode` may only *lower* the config file's mode: in an emergency,
`phaged -config /etc/phage/phage.yaml -mode alert` starts with every
enforcement feature disarmed, logs `ENFORCEMENT DISARMED` and writes a
`disarmed` audit record, instead of refusing to start; the config file must
still load. Without `-config` the mode is learn and `-mode` cannot raise it.
phaged fails closed on a full `/var` or a broken config — monitor
`phage.service` restarts (see [FORK.md](FORK.md)).

To remove everything: `sudo make uninstall` from the clone — it keeps your config
and baseline unless you also delete `/etc/phage` and `/var/lib/phage`.

## Build from source

*For development, or to run without installing.* The Go agent builds on any OS (a
stub covers non-Linux); the eBPF sensors build and run on Linux with kernel BTF.

```sh
make bpf            # compile the eBPF sensors (Linux; needs clang + libbpf)
make build          # build bin/phaged, bin/phage, bin/phage-jail
make test           # Go unit tests (build anywhere)

sudo ./bin/phaged -bpf bpf/build/sensors.bpf.o -mode learn   # run straight from the tree
sudo make install                                            # or install what you just built
```

Author locally, build and run on a Linux box. Full guide:
[development](docs/guides/development.md); first-run walkthrough:
[quickstart](docs/guides/quickstart.md).

## Honest limitations

Phage raises an attacker's cost and makes a breach survivable; it is not magic,
and saying so is part of being a security tool worth trusting:

- **Its ceiling is a kernel-level (ring-0) attacker.** Someone who can already load
  kernel code or disable the BPF LSM can blind or remove Phage. Self-defense makes
  that *noisy* and costly, not impossible.
- **Detection is behavioral and probabilistic.** A patient attacker who stays
  inside a host's learned-normal envelope can evade it, and an immature baseline
  both misses more and false-positives more. The real numbers — including where
  the false positives come from — are in [PhageBench](docs/benchmark/phagebench.md).
- **It is not a replacement for patching, least privilege, or a firewall.** It is
  the layer that assumes those will sometimes fail.

The full threat model, and Phage's own security policy, are in
[docs/concepts/threat-model.md](docs/concepts/threat-model.md) and
[SECURITY.md](SECURITY.md).

## Status

🚧 **Early but real — not yet production-ready.** The whole loop above works end to
end and is verified live against real attacks on a test server (kernel 7.0, BPF
LSM): learned-baseline detection across the seven signal classes, the graduated
reversible response, self-healing, agent self-defense, and the beginnings of
attack-surface reduction (auto-jail + an eBPF-LSM exec-lock that stops an exploited
service from spawning a shell at all). Next: automatic jail application,
baseline-driven LSM enforcement, broader kernel coverage, and a public benchmark
comparison. See the [roadmap](docs/roadmap.md).

## Contributing & security

Contributions are welcome — please keep the core principles (behavioral, not
signatures; a control plane that can't be locked out; one concern per package).
See [CONTRIBUTING.md](CONTRIBUTING.md). To report a vulnerability in Phage itself,
follow [SECURITY.md](SECURITY.md) (please don't open a public issue for it).

## License

[MIT](LICENSE).
