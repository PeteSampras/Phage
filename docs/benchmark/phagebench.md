# PhageBench — an honest evaluation

Security tools love to publish detection rates. Almost none publish their
**false-positive rate** next to it, because that number is where behavioral tools
get embarrassing. PhageBench measures both, on one reproducible harness
(upstream `scripts/bench/phagebench.sh`, not shipped in this fork), and reports
whatever comes out — including the parts that need work.

> **Fork note:** the reproduction harness this page cites lived under
> `scripts/` and has been removed from this fork, with the other upstream
> demo/bench scripts (they install setuid-root shells, `rm -rf` paths as root,
> or rsync to the upstream author's lab host). The results below are
> upstream's, kept for reference. See [FORK.md](../../FORK.md).

## What it measures
1. **Detection rate** — of a labeled attack corpus, how many Phage flags, counting
   a hit only when the *signal-specific* reason fires (not the incidental "a
   service spawned a novel program" alert every launch raises).
2. **False positives** — alerts raised while only **benign** work runs, after
   learning, expressed as alerts per window (and extrapolated per host/day).

## Methodology
On one test host (Ubuntu, kernel 7.0.0-30, x86_64), with **no signatures**:
1. **Learn** a baseline from a benign workload (admin tools, web serving, outbound
   HTTPS, a privileged op *with* a session, user-namespace use) — ~60 iterations.
2. **Detection:** one `alert`-mode agent; run each attack once; record whether its
   specific detector fired and at what score.
3. **False positives:** with the same frozen baseline, run a fresh 60-second
   benign-only workload and count every alert — each is a false positive.

## Results (this run)

### Detection — 7 / 7
| Attack | Result | Score |
|---|---|---|
| Privilege escalation (no-session root) | ✅ detected | 0.65 |
| Fileless / in-memory execution | ✅ detected | 1.00 |
| LD_PRELOAD dynamic-linker hijack | ✅ detected | 1.00 |
| Reverse-shell egress | ✅ detected | 1.00 |
| Persistence (webshell + `authorized_keys`) | ✅ detected | 0.57 |
| Kernel-enabling op (user namespace) | ✅ detected | 0.74 |
| Self-tamper (ptrace the agent) | ✅ detected | 1.00 |

Every attack was caught by its own behavioral signal, against a baseline that had
never seen it. Scores vary honestly: fileless/LD_PRELOAD/egress/self-tamper are
near-unforgeable (1.00); the webshell is 0.57 because this host *does* legitimately
write PHP, so only the unusual writer stands out — the model being correctly
relative to the host, not a fixed rule.

### False positives — and what they actually were
The first run raised **7** alerts in the 60 s window:
```
false-positive programs (comm):
  2 tail   2 sshd-session   2 sshd-auth   1 unix_chkpwd
  1 uniq   1 sort           1 sleep       1 awk
```
This is the honest, important part. **None of the false positives were attacks
misclassified.** Every one was a *benign system program the short baseline never
observed* — SSH re-authentication (`sshd-session`/`sshd-auth`), PAM's
`unix_chkpwd`, and ordinary shell text tools — flagged by the exec-novelty
detector as "a parent→child pair never seen on this host."

That is the central tradeoff of novelty-based exec detection on an **immature
baseline**: it flags benign-but-unlearned programs.

**The benchmark then drove a fix.** The RCE signal is specifically a *service*
(no session) spawning a never-seen program; a novel exec inside an *interactive*
login session is a human running commands and is expected. Down-weighting
interactive exec novelty (`execInteractiveDiscount`) **cut the window to 5 with
detection unchanged at 7/7** — a measured, thesis-aligned improvement, not a
blanket allowlist (which would create living-off-the-land blind spots). The
residual false positives are system-auth internals (`sshd`/PAM) that a
*representative* baseline — one that has seen real logins — learns, which is why
Phage ships a `learn → alert → enforce` ladder and advises a multi-day learn. The
number is a function of baseline completeness, not of the attack surface; a naive
"×1440" extrapolation assumes a frozen 60 s baseline and overstates it.

## Threats to validity (stated plainly)
- **Single host, short baseline.** 60 iterations is deliberately minimal; it makes
  the FP behavior visible but is not a production baseline.
- **Synthetic corpus.** The attacks are representative PoCs, not a live malware
  zoo; the benign workload is scripted, not a real production mix.
- **No competitor numbers yet.** The harness is built to also run Falco/Tracee on
  the same corpus; that comparison is future work and will be published with the
  same honesty, including where Phage loses.
- **Detection attribution** counts a signal-specific reason; the incidental
  launch-time exec alert is excluded, so the 7/7 is not inflated by it.

## What this benchmark drives
The FP result makes the priorities concrete and measurable:
1. **Cut exec-novelty false positives** — ✅ first step done (interactive-exec
   discount, 7→5 with detection unchanged); next, co-occurrence and time-decay
   models behind the `scorer.Scorer` seam, so a mature baseline stops being
   surprised by benign system-auth internals.
2. **Baseline maturity as a first-class metric** — report FP as a function of
   learn duration, and refuse `enforce` until the baseline is demonstrably mature.
3. **Enable-op cold start** — a host that never performs an enabling op has no
   baseline for it; decide whether such ops should default to suspicious.

(The upstream harness, `scripts/bench/phagebench.sh`, is not shipped in this fork.)
