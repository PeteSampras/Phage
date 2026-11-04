# Operating modes: the learn → alert → enforce ladder

The fastest way to kill an auto-response tool is to have it stop something
legitimate once. Phage's defence against that is a strict ladder. A deployment
only climbs when the operator is ready.

```
  learn ─────────────► alert ─────────────► enforce
  observe &            score &              score, notify
  build baseline       notify, no action    & contain
```

## learn
- Observes events and **updates the baseline** only.
- **Never** scores for action, **never** alerts, **never** acts.
- This is where every install starts. The baseline is empty, so everything would
  look anomalous — acting now would be all false positives.
- Stay here at least `learn_window` (default one week) to capture daily and
  weekly rhythms (cron, backups, deploys, maintenance).

## alert
- Scores events against the now-populated baseline and **notifies** on anomalies.
- Still takes **no action** on any process.
- This is the trust-building phase: watch what it flags, confirm the signal is
  real and the noise is low, tune `thresholds.notify`.

## enforce
- Scores, notifies, and — **only for the features the operator has switched on**
  in the config's `enforcement:` block — **acts** at/above `thresholds.contain`.
- In this fork every acting feature is **off by default**: `isolate` (network
  quarantine), `freeze` (cgroup-freeze the process tree), `self_heal`,
  `self_protect` (eBPF-LSM tamper-resistance) and `honeytokens`. With none of
  them on, enforce behaves exactly like alert. A containment rung the matrix
  picks but the config has not armed is downgraded to an alert (and the audit
  reason says so). Kill is never used.
- Each feature arms only with `mode: enforce` **and** its own key set to the
  literal `true` in the config file. A key set in learn or alert mode is a
  **startup error** — phaged fails closed rather than guessing. No command-line
  flag can enable one (`-heal`/`-protect`/`-honeytokens` are now errors), and
  `-mode` may only lower the file's mode: an emergency `-mode alert` starts
  disarmed and records a `disarmed` audit event.
- `deception.honeytokens` (decoy files) is a separate opt-in, allowed in alert
  and enforce, announced like the others.
- Every start writes a `startup` audit record (`status=armed|failed|none`, the
  config path and sha256); anything that arms is also announced with one
  `ENFORCEMENT ARMED ...` log line and an `enforcement_armed` record, so a SIEM
  can alert on it. Host-modifying features require `audit_path`.

## Containment safety — what enforce will NEVER freeze
Learned the hard way: an early enforce build froze the shell of an incoming SSH
login (a program combination its baseline had never seen) and locked the server
out. Autonomy must never be able to wedge the machine or lock out the operator,
so containment has hard guardrails that sit *above* the score (`containmentSafe`
in `internal/agent/app`):

1. **Never freeze an interactive login session.** Anything with a login
   session behind it (loginuid set) is the admin path and is exempt — Phage
   alerts, never contains, there.
2. **Never freeze the control plane.** `sshd` (recognised by its executable
   path, not its name), `systemd`, `init`, `login`, `getty`, `systemd-logind`,
   `dbus-daemon`, and `phaged` itself (recognised by pid), and their direct
   children, are never frozen.
3. **Only contain an actual privilege escalation.** A generic exec-pattern
   anomaly alerts but never freezes; freezing is reserved for an unprivileged
   process that reached root with no session — the high-confidence signal.

These are deliberate hardcoded rules, not learned behaviour: safety of the
control plane is not something to infer from a baseline.

## Why this ordering is non-negotiable
An anomaly model is only as trustworthy as its baseline. The ladder guarantees
Phage can never act on a baseline it has not earned. It also gives operators a
safe, legible path to adoption — exactly what gets a security tool deployed
rather than uninstalled.

See `internal/policy/mode` and `internal/policy/engine` for the implementation.
