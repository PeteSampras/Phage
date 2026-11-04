# Demo: the graduated-response matrix (proportional, escalating, reversible)

> **Fork note:** the reproduction harness this page cites lived under
> `scripts/` and has been removed from this fork, with the other upstream
> demo/bench scripts (they install setuid-root shells, `rm -rf` paths as root,
> or rsync to the upstream author's lab host). The results below are
> upstream's, kept for reference. See [FORK.md](../../FORK.md).

Live runs on the test server (kernel 7.0, BPF LSM active) showing Phage's
**brain**: the policy layer that, for every verdict, picks the *least-invasive
sufficient* action, **escalates** a process that keeps earning evidence, and
**de-escalates** — releases — a contained process that goes quiet. One knob,
three behaviours, all reversible.

Upstream reproduced this end to end with `scripts/bench/matrix-experiments.sh` (enforce mode,
honeytokens + self-heal on, a deliberately short 12s release lease). Every log
line below is copied from a real run of that script.

## Why a matrix
A single "contain" switch is the wrong shape. Killing a process destroys the
evidence and tips the attacker off; freezing the whole tree is overkill for a
first-seen outbound DNS packet; doing nothing is not an option in enforce mode.
The right response depends on *what* the process did and *how sure* we are. The
matrix (`internal/policy/response`) maps `(kind, score, mode, context)` to the
lowest rung that actually neutralises the behaviour:

```
none  <  notify  <  isolate  <  freeze  <  kill
```

| behaviour (kind)                    | action chosen | why that rung |
|-------------------------------------|---------------|---------------|
| outbound from a never-egressing svc | **isolate**   | cut C2, keep the process + evidence alive |
| honeytoken read                     | **freeze**    | near-certain intruder; pause for a human |
| no-session raise to root            | **freeze**    | sharpest compromise signal; pause for a human |
| persistence write (authorized_keys) | **notify** + self-heal | revert the file, keep the attacker's copy as evidence; don't freeze a maybe-legit writer |
| kernel-enabling op (userns/bpf/…)   | **notify**    | exploit *setup*, not yet an effect |
| fileless / novel exec               | **notify**    | report; auto-containing every novel exec would break legitimate JIT/runtimes |

Below `Notify` the action is `none`; `isolate`/`freeze` fire only in enforce
mode and only above `Contain`.

## A. Proportional — one attack at a time, each drawn to its own rung
Five unrelated attacks, each run once against a freshly-learned baseline:

```
   egress / reverse-shell dial-out    -> isolate [ISOLATED]
   privilege escalation (no session)  -> freeze  [FROZEN]
   persistence (authorized_keys)      -> notify  [SELF-HEALED]
   kernel-enabling (user namespace)   -> notify
   fileless execution (memfd)         -> notify
```

The same agent, same run, gives four *different* answers — it is not a single
blunt rule. Egress is severed but the process lives; the no-session root
escalation is frozen for review; the persistence write is quietly reverted
(`SELF-HEALED`) without freezing the writer; the enabling op and the fileless
exec are reported.

## B. Escalation — one process climbs the ladder
A single service process first dials out, then reads a planted credential decoy.
Phage raises its own response as the evidence mounts — **same pid, two rungs**:

```
CRITICAL score=1.00 action=isolate pid=74191 comm="bash" interactive=false ::
    an outbound connection from a program that has never egressed on this host (-> 1.1.1.1:53)
CONTAIN pid=74191 comm="bash" ISOLATED (egress severed, process alive, reversible)
...
CRITICAL score=1.00 action=freeze pid=74191 comm="bash" interactive=false ::
    read a planted honeytoken decoy "/root/.aws/credentials" — near-certain credential theft
CONTAIN pid=74191 comm="bash" FROZEN (process tree quarantined, reversible)
```

Isolation bought us the evidence (the process stayed alive and kept acting);
the decoy read then justified the stronger rung. A process already contained at
a rung is not re-actuated for a weaker verdict — the lease is just refreshed — so
escalation only ever moves *up*.

## C. Two-sided lease — isolated is released, frozen is held
Containment is a lease, not a life sentence: a contained process that draws no
new high verdict for the quiet window (12s here; default 300s) is auto-released.
But the two rungs are treated differently, and this is the important part:

```
isolated pid=74200 (egress severed, still running)   frozen pid=74204 (held)
...waiting out the 12s quiet lease...
DE-ESCALATED pid=74200 comm="bash" released (12s quiet, egress restored)
frozen pid=74204: still HELD (cgroup.freeze=1, no DE-ESCALATED) — awaits 'phage thaw'
```

- **Isolate auto-releases.** An isolated process keeps running and can still act
  and emit events, so a genuinely quiet window is *real* evidence it was benign
  or transient — restoring its egress is the right, reversible call.
- **Freeze is held.** A frozen process is silent *by construction*, so "no
  further evidence" is an artifact of the freeze, not a sign of innocence — and
  freeze is reserved for near-certain verdicts. It waits for a human (`phage
  thaw`), never a timer.

## What this experiment caught (and we fixed)
The first runs exposed two real defects — exactly what "run it for real and
document the results" is for:

1. **The sharpest signal was being averaged away.** A no-session raise to root
   scored only **0.64**, *below* the `Contain=0.8` threshold, so the matrix's
   `RaisedToRoot -> Freeze` branch was unreachable and the escalation showed up
   as a mere `notify`. Cause: `FeatRaiseNoSession` was a weighted feature,
   diluted by the calmer provenance features around it. Fix: it is now an
   **override** feature (like fileless / ld_preload) that *floors* the score on
   its own when novel — so a disguised escalation (familiar parent, usual
   lineage) still crosses into containment. It stays behavioural: a service that
   routinely setuids with no session is learned away, and an interactive `sudo`
   never sets the flag. Locked in by `TestNoSessionRootRaiseFloorsScore`.

2. **De-escalation was thawing frozen processes.** The first `releaseLoop` auto-
   released *every* rung, so a process frozen at score 1.00 for reading a
   honeytoken was released seconds later because the freeze had made it "quiet".
   Fix: only the `isolate` rung is leased; `freeze` is a hold-for-review. (Dead
   pids are also reaped so the lease table can't grow without bound.)

## Implementation
- Decision: `internal/policy/response/matrix.go` (`Decide`, `Rung`), tested in
  `matrix_test.go` (proportionality + rung ordering).
- Wiring, escalation refresh, and the de-escalation lease: `internal/agent/app`
  (`respond`, `releaseLoop`).
- The scorer floor that makes the privesc verdict reachable:
  `internal/analysis/scorer/behavioral/anomaly.go` (`overrideFeatures`).
- Harness: upstream `scripts/bench/matrix-experiments.sh` (removed from this fork).
