# Does it actually work? Before/after, with evidence

This is a results document for anyone evaluating Phage. It shows four real attacks
run on a live test server **twice** — once with Phage off (the attack succeeds),
once with Phage on (it is detected, contained, or blocked) — with the actual
output each time. Everything here is reproducible from one script
(upstream `scripts/dev/proof.sh`, not shipped in this fork).

> **Fork note:** the reproduction harness this page cites lived under
> `scripts/` and has been removed from this fork, with the other upstream
> demo/bench scripts (they install setuid-root shells, `rm -rf` paths as root,
> or rsync to the upstream author's lab host). The results below are
> upstream's, kept for reference. See [FORK.md](../../FORK.md).

- **Test host:** Ubuntu, kernel 7.0.0-30 x86_64, cgroup v2, BPF LSM active.
- **No signatures.** Phage was given ~20 seconds to learn the host's normal
  behaviour, then judged each attack against that baseline. No rule or signature
  names any specific exploit, payload, or binary.
- **Honest labels.** Each result is marked **DETECT** (flags it), **CONTAIN**
  (freezes it mid-run), or **PREVENT** (blocks it at the kernel). We do not claim
  more than the evidence shows.

## Where Phage sits in the attack chain
Phage does not guard the application vulnerability itself — the door an intruder
comes through. It guards what they do once inside. The attacker starts **outside**
the server, with no account, and breaks in through an exposed service; Phage's job
begins at the foothold.

```
[ Attacker on the internet — no account on the server ]
        |
        |  ENTRY (the payload): exploits an exposed service (web app / API) —
        |  command injection, RCE, file upload, SQLi->OS, deserialization
        |  >>> WAF / RASP territory — Phage does NOT see the payload
        v
[ Code now running as the unprivileged service user (www-data) ]  <- the foothold
        |                                          ...Phage's coverage begins here
        |  POST-EXPLOITATION — whatever the intruder does next on the host:
        |
        +-- reaches out:  reverse shell / C2       -> DETECT (egress) + BLOCK (jail)  [Sc.2, 4]
        +-- digs in:      webshell, authorized_keys-> DETECT (persistence)            [Sc.3]
        +-- escalates:    to root, no login session-> CONTAIN (freeze)                [Sc.1]
```

The same holds for an attacker who already has a low-privilege account, or an
insider: Phage judges the actions on the host, not how the actor arrived. The
"no login session" signal is how it tells an intruder's root from a real admin's.

## Summary

| # | Attack | Attacker's goal | Without Phage | With Phage | Mode |
|---|--------|-----------------|---------------|------------|------|
| 1 | Privilege escalation (RCE → root) | become root | ✅ root achieved | 🛑 detected + process tree **frozen** | enforce — **CONTAIN** |
| 2 | Reverse shell / C2 | dial out | ✅ connection opened | ⚠️ flagged **CRITICAL** with the destination | alert — **DETECT** |
| 3 | Persistence (webshell + `authorized_keys`) | survive reboot | ✅ both planted | ⚠️ flagged **CRITICAL** | alert — **DETECT** |
| 4 | Spawn a shell from the exploited service | run commands | ✅ shell ran | 🛑 **denied at the kernel** | jail (eBPF-LSM) — **PREVENT** |

---

## Scenario 1 — Privilege escalation → **CONTAIN**
A session-less service process (what an exploited web app is) reaches root via a
setuid helper — the universal shape of a local privilege escalation.

**Without Phage** — the escalation just works:
```
$ (as uid 65534, no login session) → setuid helper
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)
=> euid=0: root achieved, nothing stopped it.
```

**With Phage (enforce)** — detected on the credential change and frozen:
```
ALERT  ... comm="rootsh" uid=65534->euid=0 interactive=false ::
    raised to root with no login session behind it (never seen on this host)
CONTAIN pid=5506 comm="rootsh" FROZEN (process tree quarantined, reversible)

# verification — the offender was moved into a dedicated cgroup and frozen:
/sys/fs/cgroup/phage/quar-5506/cgroup.freeze = 1    (1 = frozen)
```
Phage moves the offending process tree into its own cgroup and freezes it — the
process is root but **cannot execute another instruction**. It is reversible: a
false positive is thawed, not killed.

---

## Scenario 2 — Reverse shell / C2 egress → **DETECT**
A service-spawned shell opens an outbound connection — the shape of a reverse
shell or a beacon phoning home.

**Without Phage** — the connection opens, unnoticed:
```
connected to 1.1.1.1:53 (reverse-shell shape)
=> outbound connection succeeded.
```

**With Phage (alert)** — flagged the instant it dialed out:
```
CRITICAL score=1.00 comm="bash" interactive=false ::
    an outbound connection from a program that has never egressed on this host;
    port 53 is unusual for this host (surprise 1.00);
    outbound connection from a process with no interactive session  (-> 1.1.1.1:53)
```
The concrete destination is in the alert and the audit trail. (In `alert` mode
Phage reports; blocking egress is a jail/enforce capability.)

---

## Scenario 3 — Persistence: webshell + backdoored key → **DETECT**
The attacker drops a webshell into the web root and appends an SSH key to
`authorized_keys` to survive a reboot.

**Without Phage** — both land, unnoticed:
```
webshell present: YES; key appended: YES
=> persistence planted.
```

**With Phage (alert)** — both writes flagged:
```
ALERT    score=0.57 comm="bash" :: a program wrote a persistence/credential file
    class it has never written on this host  (wrote /var/www/html/uploads/shell2.php)
CRITICAL score=0.83 comm="bash" :: a write to a persistence/credential file class
    rarely seen on this host  (wrote /home/demo/.ssh/authorized_keys)
```
The webshell scores lower because this host *does* legitimately write PHP (a
deploy pipeline) — only the unusual writer stands out; nothing ever writes
`authorized_keys`, so that is critical. The score is relative to *this* host's
normal, not a fixed rule.

---

## Scenario 4 — Exploited service spawns a shell → **PREVENT**
The strongest outcome: stop the exploit from running a shell at all. Phage learns
the programs a service legitimately runs, then (eBPF-LSM) denies any new one.

**Without the jail** — a process in the service's cgroup spawns a shell:
```
shell spawned as root: a reverse shell would run here
=> shell spawn succeeded.
```

**With the jail (exec-lock)** — the same spawn is refused by the kernel:
```
bash: /bin/bash: Operation not permitted
=> shell spawn DENIED at the kernel; the service keeps running.
```

---

## What this does and does not prove
- **Proven:** against behaviour it had never seen a signature for, Phage detected
  every one of these attacks, contained the privilege escalation, and (with the
  jail) prevented the shell outright — judging only against the host's learned
  normal.
- **Scope, stated plainly:** Phage is a host agent. It sees the *effect* of an
  attack on the server, not the web payload. Attacks that stay in the
  application/data layer — XSS, data-only SQL injection, IDOR, auth bypass — are
  not host-observable and are **out of scope** (they need a WAF/RASP). See
  [threats-and-behavioral-defense](../concepts/threats-and-behavioral-defense.md).
- **Undiscovered vulnerabilities:** because detection is behavioural, a brand-new
  (zero-day) exploit is still caught **if it produces one of these universal host
  effects** — a shell, a root transition, a persistence write, an outbound
  connection. The signature never mattered.

## Reproduce it yourself
```sh
make bpf && make build            # build on the Linux host
# upstream: sudo ./scripts/dev/proof.sh — removed from this fork
```
The script learns a baseline, then runs each attack with and without Phage,
printing the evidence above. It restores the box on exit.
