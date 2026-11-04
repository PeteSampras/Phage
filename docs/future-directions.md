# Future directions — prioritized R&D map

A curated, de-duplicated synthesis of a research pass across five dimensions
(universal reach, control-panel/hosting, novel detection signals, autonomy &
response, competitive differentiation). Ranked by **impact on the project's goal**
(build credible reputation → in-demand eBPF/security skills), balanced against
solo-maintainer effort. Honest about what is *not* novel.

Current shipped & live-verified baseline: privilege-escalation, exec/RCE (+
fileless, + LD_PRELOAD), egress/C2, persistence writes, kernel-enabling ops (+
eBPF-rootkit load); containment via reversible cgroup-freeze, seccomp jail, and
eBPF-LSM per-service exec-lock.

## The honest frame (what actually differentiates Phage)
The whole OSS eBPF runtime-security field (Falco, Tetragon, Tracee, Wazuh) is
**rule/signature-driven and Kubernetes-shaped**, and the enforcing ones **kill**.
Each primitive Phage uses exists somewhere; the defensible novelty is the **closed
loop in one static binary, with no cluster**: *unsupervised per-host learned
baseline → reversible autonomous response → explainable verdict.* Say the weak
spots out loud (no ecosystem, one maintainer, unproven fleet-scale FP rate) — that
honesty is itself a hiring signal. Do **not** claim "AI detection", "beats
CrowdStrike", "provably secure", or that the eBPF-LSM exec-lock is novel in
isolation (it isn't — AegisBPF/eBPFGuard/BPFContain exist; the *learned+reversible+
explainable loop* is the new part).

## Cross-dimension consensus (independently surfaced by ≥2 research threads — build these)
1. **Agent self-defense / anti-blinding** — detect attempts to kill, pause, ptrace,
   unhook (`bpf()` detach), or silence Phage, in-kernel, plus a **dead-man's-switch**
   that treats *absence* of telemetry as an alert. Directly answers the #1 2025
   evasion trend (blinding, not killing) and the standing "root just disables eBPF
   tools" critique. Honest ceiling: a ring-0 attacker already more privileged than
   Phage — document it loudly.
2. **"Provably won't lock you out" guardrail** — turn the sshd-lockout scar into a
   marketed feature: every enforcement action is a TTL lease with a blast-radius
   pre-check (never PID1/sshd/the agent/the admin's session) and a reachability
   prober that auto-reverts anything that severs the management plane. This is the
   trust unlock that makes `enforce` adoptable at all.
3. **The 30-second "freeze, not kill" demo** — one asciinema/GIF against a real CVE
   on a plain VPS: detect → freeze the attacker mid-exploit → show the explainable
   "why" → inspect → resume/jail. The adoption hook; no competitor can tell the
   "pause the attacker and look at them" story.
4. **Explainable verdict as structured provenance** — machine-readable JSON + a
   one-paragraph English causal narrative per verdict. The substrate for the
   benchmark, the incident report, and the triage story.

## Build ladder (recommended sequence)

### Tier 0 — Package & prove what exists (days)
- The freeze demo (#3 above) — pin a <60s GIF in the README.
- Structured explainable verdicts (#4) — extend the reasons we already emit.

### Tier 1 — The credibility knockout (weeks)
- **PhageBench** — ✅ **v1 shipped** ([benchmark](benchmark/phagebench.md),
  upstream `scripts/bench/phagebench.sh`, not shipped in this fork): learns a benign baseline, then reports detection
  rate (7/7 on the attack corpus) **and** false positives from a benign-only
  window, with an honest breakdown showing the FPs are unlearned benign *system*
  programs (the exec-novelty-vs-baseline-maturity tradeoff). Remaining: run the
  same corpus against Falco/Tracee and publish the comparison; report FP as a
  function of learn duration.

### Tier 2 — The "self-defending" thesis made real (consensus; M)
- Agent self-defense / anti-blinding + dead-man's-switch (consensus #1).
- Never-lock-out guardrail, chaos-tested (consensus #2).

### Tier 3 — Autonomy depth + the "immune-system reel" (M)
- **Honeytokens fused into the kernel sensor** — ✅ **shipped** (`phaged
  -honeytokens`, [demo](demo/honeytokens.md)): decoys planted only where no real
  file exists, inodes registered in-kernel, any read → CRITICAL, removed on exit.
  Highest-signal detector; near-zero FP.
- **Per-process net-quarantine** — ✅ **shipped** ([demo](demo/network-quarantine.md)):
  egress/C2 verdicts in enforce sever the offending service's outbound network via
  `cgroup/connect` programs attached to its cgroup (catches forked children),
  process stays alive, reversible via `phage thaw`. Follow-up: `cgroup_skb/egress`
  to also cut established sockets; a TTL auto-release.
- **Self-healing restore** — ✅ **shipped** (`phaged -heal`,
  [demo](demo/self-healing.md)): snapshots sentinel files and, on a malicious-write
  verdict, atomically restores the known-good version and quarantines the
  attacker's. Verdict- and snapshot-gated so legit edits aren't reverted.
- These compose into a ~90s reel: honeytoken read → net-quarantine (not kill) →
  self-heal authorized_keys → attacker tries to kill the agent → LSM denies & freezes
  → signed incident report → time-travel replay → `thaw` reverses everything.

### Tier 4 — New high-SNR detection signals (S–M each; pick the sharp ones)
- **ptrace / process injection** (near-zero baseline on a server; S).
- **Supply-chain install-hook abuse** (Shai-Hulud npm worm pattern; reuses exec
  ancestry; S; very topical).
- **Lateral movement** — a leaf host suddenly spraying internal SSH/:22 (S).
- **Anti-forensic** — `wtmp`/`btmp`/history truncation, timestomp via `utimensat` (S).
- **Credential/secret theft** — novel reader of `/etc/shadow`, `~/.aws`, K8s SA
  token, IMDS (`169.254.169.254`), chained to novel egress (S–M).
- **Cryptominer behavioral triad** — learned CPU envelope break + MSR writes +
  stratum beacon cadence (M; the best standalone live demo).
- **Container-escape chain** — extend the shipped `create_user_ns` hook to
  `setns`/host-mount/`release_agent`/`core_pattern` writes, per-workload (M).
- **DNS tunneling / DoH C2** — process-identity + resolver-bypass + entropy, learned
  per host (not volume thresholds) (M).
- **Circadian multiplier** — learn each identity's daily rhythm; "right action, wrong
  time" boosts surprise on every other detector (S, cross-cutting).

### Tier 5 — eBPF depth / career & frontier (M–L)
- **io_uring operation tracing** — attribute `IORING_OP_*` I/O per process; catch a
  process doing file/network I/O *only* via io_uring to dodge syscall telemetry
  (the leading 2025 evasion). Sharp, eBPF-forward.
- **eBPF-rootkit detection deep-dive** — lean into detecting/tearing down malicious
  BPF loads (we already hook `bpf_prog_load`); write it up → a conference talk
  (eBPF Summit / FOSDEM / Linux Security Summit Europe).
- **Provenance-graph sequence model** behind `scorer.Scorer` — score multi-hop path
  novelty (`sshd→python→sh→curl→IMDS`), not just single edges. The 2025/26 research
  frontier; the strongest "eBPF + explainable ML" résumé signal. L effort; keep on
  learn→alert well before enforce.

### Tier 6 — Reach & market (architectural; M–L)
- **Tiered sensor backend + startup capability negotiation** — a `SensorProvider`
  interface emitting one normalized schema; probe BTF/ring-buffer/CAP_BPF/BPF-LSM/
  fanotify/audit per event class and bind the best backend *per class*. Lets Phage
  run (and enforce) from BTF-less CentOS 7 to a locked-down distroless pod — which
  Falco/Tetragon cannot. The keystone for universal reach.
- **fanotify enforcement** (`FAN_OPEN_EXEC_PERM`) — blocking, reversible enforcement
  on kernels without BPF-LSM; headline "defends where Falco can't even load."
- **Static musl single binary + `.deb`/`.rpm`/OCI + fidelity-tagged verdicts**
  (confidence scales with sensor tier; honest by construction).
- **Per-tenant (per-cPanel-user/vhost) behavioral baseline** — generalize the
  baseline key from host to (host, tenant); flagship demo: a real RCE in one
  tenant's WordPress → name the user, freeze *only* that tenant's cgroup in ms,
  neighbors keep serving. Owns the cPanel/VPS market Imunify360 (closed, PHP-layer,
  no kernel truth, no per-tenant syscall baseline) can't match. Pair with an open,
  panel-agnostic auto-suspend bridge (cPanel/Plesk/DA/CyberPanel/Hestia).

### Tier 7 — Ops & fleet (later; adoption/enterprise)
- Live `phage top` TUI + Prometheus/OTel `/metrics` + syslog/CEF/Slack/webhook sinks.
- Signed, ATT&CK-mapped incident packet from the event graph.
- Time-travel incident replay + "would my new enforce rule have frozen sshd?" policy
  regression simulator.
- Signed/attested policies (minisign/sigstore); open, privacy-preserving "herd"
  intel (opt-in; v2).

## For the EU-job narrative specifically
The three artifacts that convert work into a hire: **(1)** the pinned freeze demo,
**(2)** PhageBench with honest FP numbers (the knockout), **(3)** one deep eBPF
technical blog + a submitted talk (io_uring evasion or eBPF-rootkit or the
provenance-graph model). A brutally honest README "Scope & Limitations" section is,
paradoxically, a strong hiring signal.
