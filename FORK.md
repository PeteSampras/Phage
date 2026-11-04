# About this fork

This is a hardened fork of [Phage](https://github.com/AzozzALFiras/Phage), based
on upstream commit `9757354`. It keeps all of upstream's enforcement code
(isolate, freeze, network quarantine, self-heal, self-protect, honeytokens,
`phage-jail`) so that it is still available. The difference is that **nothing
that changes the host arms unless the operator turns it on explicitly in the
config file.** Out of the box the fork learns, then alerts.

Upstream's MIT `LICENSE` and copyright notice are unchanged. The commits on top
of `9757354` record every change.

> **Recommendation: keep `enforcement.self_heal` disabled** until the sensor
> records the dev+ino of the inode that was actually opened for writing
> (in-kernel, from `f_inode`). Two gaps remain until then (see Known open
> items): a writer holding an open fd can over-mount its own view to defeat
> the inode check, and data written later through an fd opened earlier is
> never seen. Alert-only (shadow) use — learn/alert, or enforce without
> `self_heal` — does not depend on any of this.

## Default posture

| Mode | What it does |
|---|---|
| `learn` (default) | builds the baseline; no alerts, no actions |
| `alert` | scores and alerts; no actions (decoys only if `deception.honeytokens`) |
| `enforce` | scores and alerts, and acts **only through the features enabled in `enforcement:`** |

Every host-modifying feature is **off by default**:

| Config key | What it changes on the host | Allowed in | Upstream armed it when |
|---|---|---|---|
| `enforcement.isolate` | cuts a process's egress (eBPF cgroup network quarantine) | enforce | in any `mode: enforce` |
| `enforcement.freeze` | freezes the process tree with the cgroup freezer | enforce | in any `mode: enforce` |
| `enforcement.self_heal` | rewrites sentinel files (`authorized_keys`, cron, `ld.so.preload`) | enforce | `-heal` was given, **in any mode** |
| `enforcement.self_protect` | an eBPF-LSM program that refuses signals sent to the agent | enforce | `-protect` was given, **in any mode** |
| `deception.honeytokens` | creates decoy credential files | alert, enforce | `-honeytokens` was given, **in any mode** |

With no `enforcement:` key on, `enforce` behaves exactly like `alert`.

## Reporting: novelty rows, heartbeat, baseline review

None of this acts on the host or arms anything; it only writes files phaged
owns. It makes Phage a second source for homelab-next's novelty analyzer
(ADR-0036 decisions 6-7) and observable as a SOC sensor (see
[docs/wazuh.md](docs/wazuh.md)).

**Novelty rows are opt-in** (`output.novelty_path`, unset by default;
`/var/lib/phage/novelty.jsonl` is the conventional path; written in alert
and enforce mode). Setting the path **requires** `output.tlp`,
`output.entity_kind` and `output.entity`; there are no defaults for them.
One JSON line per verdict at or above `thresholds.notify`, in the shape of
homelab-next's `novelty_finding` table:

| Column | Phage writes |
|---|---|
| `source` | `output.source`, default `phage-host` (never `lake-novelty`) |
| `source_kind` | always `heuristic`: advisory, never a basis to act alone |
| `profile` | the event kind: `exec`, `connect`, `file-write`, `enable`, `creds-change`, `self-defense`, `honeytoken` |
| `entity_kind`, `entity` | `output.entity_kind` and `output.entity`: the text a lake profile uses for this host (an `ip` in canonical form; a `host` name in lower case), so `corroborate` sees one entity. A host name rarely matches a lake profile, which is why there is no default |
| `value` | the concrete object: the path (file-write, honeytoken), `ip:port` (connect), the op (enable), the signal (self-defense), else the executable. Absent on a `burst` row |
| `status` | `finding`, `unlearned` or `burst` (below) |
| `score`, `confidence` | findings only: the **verdict's** score (Phage's weighted scorer, not the lake's surprise x confidence), and the confidence of its top reason |
| `support`, `entity_total` | the top reason's feature: **raw** counts (times the value was learned, observations of the feature), not the lake's decayed support |
| `count` | 1 (one row per event); on a `burst` row, always the cap + 1 (never the true total, which the heartbeat's `novelty_over_cap` carries) |
| `time`, `as_of` | `time` is when the kernel saw the event (back-dated by the measured lag), not the start of a scoring window as for the lake analyzer; `as_of` is when the row was written |
| `uid` | `phage-` + a digest of source, profile, status, entity kind, entity, value and the start of the event's `output.novelty_bucket` (default 1h). The lake keys on (source, uid), so a repeat in the same bucket, including one re-sent after a restart, is one row there |
| `message`, `reasons` | the explanation, each reason with its arithmetic, and `baseline sha256:<hex>` |
| `tlp` | `output.tlp` |

The schema is copied into `internal/novelty/testdata` (homelab-next
`47042a0`), and every row shape is validated against it in the tests.

- **`unlearned` fixes a silence.** The scorer treats a feature it never
  observed as neutral, so a host that never egressed while learning scored
  its first egress 0 and said nothing. Now, when *every* feature key of an
  event's class has no observation in the baseline, phaged logs `UNLEARNED`
  and writes an `unlearned` row with no score. It is never a verdict: no
  response, no response record, nothing acted on. A class with any
  observation is scored as before; a single never-observed key inside a
  learned class is still neutral.
- **Not while the baseline is empty or thin.** With no baseline every class
  is unlearned, so every event would become a row, flood the file and the
  SIEM, and make one baseline-less host corroborate every lake finding.
  Until the baseline holds `learn.min_baseline_samples` feature observations
  (default 5000; each learned event adds one per feature it carries) its
  state is `warming` (`no_baseline` when empty): scoring continues (it is
  discounted on thin features anyway) but nothing is reported as unlearned.
  The threshold is host-wide, not per feature class: a host whose baseline is
  ready overall still reports a class it never saw as unlearned (that is the
  point), and the per-feature confidence ramp in the scorer handles classes
  that are merely thin.
  The state is logged loudly at startup (`BASELINE NOT READY`), and carried
  in the `startup` and `heartbeat` records (`baseline_state`) and in
  `phage status`.
- **Per-bucket cap.** `unlearned` rows and `finding` rows each have their own
  budget of `output.novelty_max_per_bucket` (default 20) new rows per
  profile and entity in one uid bucket, so a flood of one never hides the
  other. Findings scoring at or above `thresholds.contain` are never capped.
  The first row past a budget is replaced by a single `burst` row (no value,
  no score; a signal in the schema), one per status, profile, entity and
  bucket, and phaged logs one `NOVELTY BURST` line; the rest are only counted.
  **A burst row's `count` is always the cap + 1**, not the total: the total is
  not known when the row is written, and is the heartbeat's
  `novelty_over_cap`. A scan, a flood of new destinations, or an attacker
  generating noise costs a few rows per hour, not one per event, and cannot
  push a high-scoring finding out.
- **Writing once.** phaged remembers a uid for two buckets and writes it once
  in that time ("a repeat within one bucket" above); the dedupe set holds at
  most 65536 uids and is swept for expired ones at most once a minute. Past
  that bound rows are written without dedupe, still under the cap.
- **TLP: required, and never `red`.** Only `clear`, `green`, `amber` and
  `amber+strict` are accepted, exactly (`TLP:AMBER`, `Amber`, `white` are
  refused). `red` is refused with an error: homelab-next's analyzer-output
  writers must read below `red` (ADR-0036), so a red row could never be
  written to the lake. The sink itself refuses a row with any other label.
  The label is per host, and only as good as the operator's judgement of how
  widely its paths, addresses and program names may be shared. Rows that
  reach the lake through homelab-next's log pipeline take their label from
  the route the pipeline assigns, not from this column; and the Wazuh agent
  ships the file whatever the label says.
- The file is opened like the audit trail (`O_APPEND|O_NOFOLLOW|O_CLOEXEC`,
  0600, regular files only; an existing file must be owned by phaged's euid
  and have one link). It rotates to `novelty.jsonl.1` at
  `output.novelty_max_bytes` (default 64 MiB); with `0` it never rotates,
  and logrotate `copytruncate` is safe because every write is `O_APPEND`.
  A sink that cannot be opened stops startup. A failed write is logged
  (`NOVELTY SINK WRITE FAILED`, at most once a minute with a count) and
  counted in the heartbeat; it never stops the daemon.
- **There is no ingest path yet.** Nothing in this repository writes the
  rows into the lake's `novelty_finding` table, and they must be written
  through the lake's writer under Phage's own source (ADR-0036 decision 6).
  The planned follow-up is in homelab-next: an `hnx novelty ingest`
  (a checkpointing ingestor with a per-host mark).

**Heartbeat.** Every `output.heartbeat_interval` seconds (default 60), in
every mode, a `heartbeat` audit record: events/s, ring-buffer **drops** in
the interval and in total, enrichment lag (kernel timestamp to enriched
event, average and maximum ms), novelty rows/suppressed/over-cap/errors,
the baseline's state and size, baseline overflow, checkpoint errors, the
mode, the armed features and the baseline's sha256. Drops come from a per-CPU counter in `sensors.bpf.c` that every
sensor increments when `bpf_ringbuf_reserve` fails; a drop is also logged
(`SENSOR DROPS`). `phage status` shows the same numbers. A SIEM alerts on
drops and on the heartbeat going missing (`deploy/wazuh/`).

**Baseline.** In learn mode the baseline is checkpointed every
`learn.checkpoint_interval` (default 10m) when it changed, by the same
atomic temp-file, fsync, rename and directory fsync as the shutdown save, so a crash loses at most
one interval; a failed checkpoint is logged (`BASELINE CHECKPOINT FAILED`)
and counted. The sha256 of the baseline file is logged at startup and
carried in the `startup` and `heartbeat` records. Each feature learns at most
`learn.max_values_per_key` distinct values (default 10000): a new value past
the cap still counts as an observation but is not learned (so it stays
novel), is counted as overflow (persisted in the baseline, shown in the
heartbeat and `phage baseline show`), and is logged once per feature. In
alert mode such a value is novel because of the cap, not necessarily because
the host never produced it, so its confidence is halved and its reason says
`[feature at cap; value not learned]`. A baseline that already holds more
values than the cap (an older baseline, or a lowered cap) keeps them all;
only new values are refused.

Before switching a host from learn to alert, review what it learned:

```sh
cp /var/lib/phage/baseline.json /root/baseline-week1.json   # keep a copy now and then
phage baseline show /var/lib/phage/baseline.json            # per feature: observations, distinct, established, overflow
phage baseline diff /root/baseline-week1.json /var/lib/phage/baseline.json
```

`diff` lists, per feature, values added and removed, and values that became
established (will no longer alert) or stopped being so. Ports and flags read
as numbers; program, pair and file-class values are stable hash ids. Both
commands only read the files (regular files only; a FIFO is refused rather
than waited on), print every key and value escaped, and need no daemon.

## Turning features on

These features can be enabled **only** in `/etc/phage/phage.yaml`:

```yaml
mode: enforce
audit_path: /var/lib/phage/audit.jsonl   # the default; required for any feature below
enforcement:
  isolate: true
  freeze: false
  self_heal: true
  self_protect: false
deception:
  honeytokens: false
release_after: 300                        # >= 1 second
```

After editing the file, run `systemctl restart phage`.

**What the config file accepts**

- Only the literal YAML values `true` and `false` are accepted. `yes`, `on`,
  `1`, `"true"` and `True` are all rejected.
- Phaged refuses to start if:
  - any `enforcement:` key is on while the mode is learn or alert;
  - `deception.honeytokens` is on while the mode is learn;
  - any of these features is on while `audit_path` is empty.

**What the command line can do**

- **No command-line flag can enable a host-modifying feature.** `-heal`,
  `-protect` and `-honeytokens` are now errors, and each error names the config
  key that replaced the flag.
- `-mode` can only **lower** the config file's mode. It can never raise it.
  - Without `-config` the mode is the default, `learn`, so `-mode alert` and
    `-mode enforce` are refused there too. To run in alert by hand, write a
    config file with `mode: alert`. (`-mode learn` is accepted.)
  - Emergency downgrade: run `phaged -config … -mode alert` (or `learn`). This
    starts with every feature that mode does not allow switched off. It logs an
    `ENFORCEMENT DISARMED` line and writes a `disarmed` audit record. It does
    not fail on validation of the switched-off keys. **It still needs a config
    file that loads**: a file with a YAML error, an unknown key or a non-literal
    boolean stops startup whatever `-mode` says. To recover from a broken file,
    fix it or point `-config` at a known-good copy.

**How a containment rung falls back**

- If the response matrix picks a containment rung that is not armed, the agent
  alerts instead. The audit record shows `outcome: skipped:<feature> not armed`.
- If isolate is armed but its eBPF program fails to load, the agent falls back
  to freeze, but only when freeze is also armed.
- The agent never kills a process.

## What a SIEM sees

All records go to the audit trail. It is on by default at
`/var/lib/phage/audit.jsonl`, which is opened with `O_NOFOLLOW|O_CLOEXEC` and
created 0600.

- **`startup` record, on every start:** `status` (`armed` | `failed` | `none`),
  `mode`, `features` (what armed), `failed` (requested but not armed, e.g.
  `self_protect` without BPF LSM), `disarmed`, `config_path`, `config_sha256`
  and `version`. Alert on `status != none`, or on an unexpected
  `config_sha256`.
- **When anything armed:** the log line
  `ENFORCEMENT ARMED event=enforcement_armed status=armed mode=… features=… failed=… config_path=… config_sha256=… version=…`
  and a matching `enforcement_armed` record. When nothing armed, the startup
  line carries `status=` instead of the ARMED header.
- **On a `-mode` downgrade:** a `disarmed` record.
- **Response records**, written *after* actuation:
  - `requested`: the rung the matrix chose;
  - `action`: the rung actually applied;
  - `outcome`: `contained`, `notified`, `skipped:<why>` or `failed:<err>`.

  `phage events` shows the same fields. A write-open by a process that is already
  contained still gets a response record, with `outcome: already_contained`.
- **Self-heal records** (`kind: self_heal`), one per heal attempt: `outcome`
  is `healed`, `unchanged` or `failed:<err>`, along with the `path`, the
  `evidence` location, and the writer's pid and comm.
- **`startup` also carries** `baseline_sha256` (`none` on a fresh host),
  `baseline_state` (`no_baseline`, `warming` or `ready`) and, when the
  novelty sink is on, `novelty_path`, `novelty_entity`
  (`<entity_kind>:<entity>`) and `tlp`.
- **Heartbeat records** (`kind: heartbeat`), every
  `output.heartbeat_interval` seconds in every mode, with a `health` object
  (see Reporting above). Every `health` field is always present, so a rule can
  match a zero.
- **Failing to write a startup, arming or disarm record is fatal.** A failed
  response, self-heal or heartbeat record during the run is only logged; a
  missing heartbeat is itself what the SIEM alerts on.

## What stops phaged from starting (monitor it)

phaged fails closed at startup. Under `Restart=on-failure` (every 5 s) any of
the following becomes a crash loop that leaves the host **unmonitored**:
- a full or read-only `/var`: the audit trail cannot be opened, or the startup
  or arming record cannot be written;
- a config file that does not load: YAML errors, unknown keys, non-literal
  booleans, an invalid combination, or a missing file;
- a removed flag (`-heal`, `-protect`, `-honeytokens`) left in a drop-in;
- a `-mode` that would raise the file's mode;
- in alert or enforce mode, a novelty sink (`output.novelty_path`) that
  cannot be opened (a symlink, a FIFO, a hard link, a file owned by another
  uid, a full or read-only `/var`);
- an invalid `output:` or `learn:` value: `output.novelty_path` set without
  `output.tlp`, `output.entity_kind` and `output.entity`; a TLP of `red` or
  not one of the canonical labels; a malformed source or entity, an
  upper-case host entity; an out-of-range interval or cap;
- a corrupt baseline (`/var/lib/phage/baseline.json` that is not valid JSON —
  e.g. truncated by a full disk). A *missing* baseline is fine (fresh host);
  to recover, move the bad file aside (this restarts learning);
- the eBPF sensor object failing to load (missing/wrong `-bpf` path, a kernel
  without BTF, or missing privileges). The optional objects (network
  quarantine, self-protect) only make their feature `failed`; they do not stop
  startup.

Alert on it: watch `systemctl show -p NRestarts,ActiveState phage` (or the
node-exporter systemd collector), or add an `OnFailure=` unit that pages, and
alert on disk space for `/var/lib/phage`. `deploy/wazuh/` does this for Wazuh:
a rule for three starts within ten minutes, an agent-side check of
`phage.service`, an agent-side check that fires when no heartbeat has been
written for three intervals, and a rule for three heartbeats in a row with no
events. A start that fails before writing its `startup` record (a broken
config, a full `/var`) never reaches the startup-counting rule; the service and
heartbeat checks catch it (Wazuh rules cannot fire on an absent event; see
[docs/wazuh.md](docs/wazuh.md)).

## Building a release

`make release` (`scripts/build/release.sh`) is the in-house build of what
gets deployed. It builds from the checked-out commit and refuses a dirty tree
(`ALLOW_DIRTY=1` for a throwaway, marked `-dirty`), and requires the Go
toolchain to be exactly the version `go.mod` pins. It runs with
`GOTOOLCHAIN=local`; `GOTOOLCHAIN=go<that version>` is also accepted, and go
then fetches exactly that toolchain, checksum-verified. Whatever the caller's
environment or go env file says, it builds with `GOENV=off`,
`GOWORK=off`, `GOPROXY=https://proxy.golang.org`, `GOSUMDB=sum.golang.org`,
and no `GONOSUMDB`/`GONOPROXY`/`GOPRIVATE`/`GOINSECURE`, and fails if any
binary embeds a module replacement (`=>` in `go version -m`). clang and
llvm-strip are resolved once, passed to `make bpf` explicitly and recorded
with their paths in `BUILDINFO`; the Makefile deletes a target whose recipe
failed (`.DELETE_ON_ERROR`). It regenerates
`vmlinux.h` from the build host's kernel BTF (`BPFTOOL=` names a versioned
bpftool), rebuilds every eBPF object, and builds `phaged`, `phage` and
`phage-jail` with `CGO_ENABLED=0 -trimpath -buildvcs=true` and an empty build
id. It then checks with `go version -m` that the commit is embedded,
unmodified. Output goes to `dist/release/<version>/`: binaries, `bpf/*.bpf.o`,
the unit, the example config, the heartbeat check, the licence, a `BUILDINFO`
(toolchains including llvm-strip and bpftool, the `vmlinux.h` sha256, the
kernel), and `SHA256SUMS` over all of it. Two clean builds of one commit on one
host were byte-identical. The eBPF objects are compiled with
`-ffile-prefix-map=$(CURDIR)=.`, so they are byte-identical from two different
checkout directories too (checked); `llvm-strip` failing now fails the build.

```sh
git checkout <reviewed-commit-sha>
make release                                   # or GOTOOLCHAIN=go1.25.0 make release
(cd dist/release/<version> && sha256sum -c SHA256SUMS)
sudo make install BIN=dist/release/<version>   # installs that release's binaries, eBPF objects and heartbeat check
```

The eBPF objects are CO-RE, but their bytes depend on the clang version and
the build host's `vmlinux.h`; `BUILDINFO` records both.

## What changed and why

These findings come from a read-only security review of `9757354`, and from a
design review and security audit of the first hardening round. Most findings
are fixed across more than one commit (for example, the config gate and the
docs moved together). `git log 9757354..` lists each commit.

1. **HIGH: self-heal ran in alert mode.** The `-heal` flag armed it in any mode.
   *Fix:* every host-modifying feature is gated on its mode and its own config
   key, as described above.
2. **HIGH: self-heal could be steered into writing arbitrary files as root.**
   The restore wrote `path + ".phage-heal"` with `os.WriteFile`, which follows
   symlinks, and the watched `/home/*/.ssh/authorized_keys` files sit in
   directories the user owns. *Fix:*
   - Paths are resolved with `openat2(RESOLVE_NO_SYMLINKS)`, or with an
     `O_NOFOLLOW` walk on kernels without openat2. All later steps use file
     descriptors.
   - The parent directory must be owned by root or by the file's owner, and must
     be the same dev/inode it was at snapshot time.
   - The restored copy is created `O_CREAT|O_EXCL|O_NOFOLLOW` under a random
     name **beside the target, through the verified parent directory fd**. This
     means it gets the directory's default SELinux context; the snapshot's
     `security.selinux` label is also re-applied, best effort.
   - The copy is given the original uid, gid and mode with `fchown`/`fchmod`,
     fsynced, and then `renameat`-ed over the target.
   - Whatever an attacker leaves at the path (an oversized file, a symlink, a
     FIFO) is inspected with `fstatat(AT_SYMLINK_NOFOLLOW)`. It is never
     followed, but it is replaced. The evidence copy is truncated, or records
     the symlink's target. Only a directory at the path is refused.
   - Only one heal per file can be pending at a time.
   - The quarantine directory is capped at 64 MiB, split into two pools that
     are pruned independently, oldest mtime first, with each prune logged.
     Evidence for root-owned sentinels goes in one pool and evidence for
     user-owned ones in the other, so a user rewriting their own
     `authorized_keys` can never evict the evidence of an attack on a
     root-owned file.
3. **Self-heal triggered by write-opens in another mount namespace.** A container
   writing its own `/root/.ssh/authorized_keys` produced the same path as the
   host's file. A mount-namespace comparison (the first fix) was wrong in the
   other direction: `unshare -Urm sh -c 'echo k >> ~/.ssh/authorized_keys'`
   is in a new namespace but still writes the host inode, so it was alerted
   and never healed. Later rounds found that resolving the writer's view is
   **not sufficient on its own**:
   - An unprivileged user can write a private copy and then `rm` it, so the
     view no longer resolves (fixed in round 3).
   - The same user can write a private copy and then `umount` its tmpfs, so
     the view resolves to the *host* inode again (round 4).
   - The gate compared the writer with the *snapshot* owner, not the current
     one (round 4).
   - In a directory the attacker can write (group/world-writable, or sticky
     with the file absent), the attacker could plant its own file, so that
     it is the current owner and passes the gate, then delete it during the
     heal delay. Heal skipped the owner check on a missing file and recreated
     a root-owned file (round 5).

   *Fix (current):* the gate has two conditions, both required.
   - **The writer could have written the host file.** Its real uid in the
     init namespace is 0 or the file's **current** owner, read at decision
     time through the verified directory. An absent file has no owner, so
     only a root writer qualifies. The gate checks this before the inode
     comparison.
     Heal re-checks the uid under the verified directory fd before staging
     the restored copy. At that point a non-root writer may restore only a
     file that exists and is owned by that writer and by the snapshot owner,
     and an absent file is recreated only for a root writer. The check is
     made **before staging, not atomically with the rename**: in her own
     directory the owner can still race the rename, for example by deleting
     the file or swapping the staged copy after the check. That can only
     restore *her own* file, with *her own* snapshot content and ownership,
     so she gains nothing she could not do directly. The audit record can
     then say `healed` even though she swapped the staged copy, so treat
     `healed` on a user-owned sentinel as best-effort. When several events
     are folded into one rerun (the dirty bit), the least-privileged writer's
     uid is used: non-root wins over root, and two different non-root uids
     refuse.
   - **The writer's view does not name a different file.** The path, resolved
     in `/proc/<pid>/root` with `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS)`,
     must be the host file's dev+ino. A container's own copy is never healed
     over the host file, even for root. If the view cannot be resolved, the
     uid condition alone decides, and Heal then compares the host file with
     its snapshot.

   In addition:
   - **Heal refuses (audited `failed:`) if the file's current owner differs
     from its snapshot owner**, so it never hands a file back to an old owner.
   - **Sentinels in a group- or world-writable directory (sticky or not) are
     never watched** ("not watching" at startup), and a directory that becomes
     shared later is refused at heal time.
   - **Group and ACL writers are never healed.** Only uid 0 or the file's
     owning uid can trigger a heal. Write access granted to a group, or by a
     POSIX ACL, is invisible to the check, so such a writer's event is
     alerted but never healed. A directory whose write access comes from an
     ACL rather than from mode bits is *not* detected as shared, so do not
     watch sentinels in such directories.
   - **PID reuse can only suppress a heal.** If the writer's pid is reused
     before the gate looks, the gate checks the new process's view of the
     path. That can only turn up "a different file" and veto the heal. It
     cannot authorise one, because the uid comes from the kernel event, not
     from the pid.

   This narrows who can trigger a wrong heal; it does not make self-heal safe:
   - Only real uids are checked; the sensor records no euid/fsuid for file
     events, so a setuid-root writer started by a user is not healed.
   - **Container root without a user-namespace remap is real uid 0 and counts
     as root.** It can make the agent revert a host sentinel to its startup
     snapshot, even if it cannot write that file, by writing and removing a
     private copy at the same path.
   - The file's current owner can revert an admin's edit to their own file,
     but gains nothing they could not do directly.

   Write-open events that arrive during a running heal set a dirty bit, so
   the heal runs once more rather than missing them. Every heal attempt is
   audited.
4. **MEDIUM: trust was based on `comm`, which the attacker controls.**
   - The agent now recognises itself by its own tgid.
   - Only **pid 1** counts as the supervisor. The launcher is trusted only when
     `dev.trust_launcher_signals: true` is set, and it is re-read with
     `getppid` at decision time. The self-protect LSM's launcher slot is set to
     pid 1 unless that setting is on; when it is on, the slot is **fixed at arm
     time** to the parent at that moment, and is not re-read. If the launcher
     exits, its pid stays allowed to signal the agent until phaged restarts.
     This is one more reason the setting is for hand runs only.
   - sshd is recognised by identity. The inode of `/proc/<pid>/exe` must be one
     of the installed sshd binaries; these are resolved at startup, and again on
     a miss so package upgrades are picked up. An unlinked listed binary
     (`(deleted)`, nlink 0) also counts. In addition, the process's sshd
     ancestry must lead to a uid-0 sshd whose parent is pid 1.
   - A process merely *named* `sshd*` is still never contained, because
     misjudging the real sshd would lock the operator out. It is logged as
     `WARNING … UNVERIFIED`.
   - The never-contain guardrail now covers isolate as well as freeze.
5. **`-protect`, `-heal` and `-honeytokens` existed only on the command line
   and armed in any mode.** *Fix:* they are now config keys. The flags are
   errors.
6. **LOW: control socket.** *Fix:*
   - The socket is bound under umask 077, so it is never group- or
     world-accessible.
   - `SO_PEERCRED` must report uid 0. A rejected peer receives
     `permission denied`, and the attempt is logged.
   - Connections have a deadline.
7. **MEDIUM: journal line forging.** *Fix:* attacker-influenced text is escaped
   exactly once, at output, by `logsafe.Clean` in both the daemon log and
   `phage events`. The audit trail stores raw values, since JSON escapes them.
8. **Honeytokens.**
   - They are now their own opt-in, `deception.honeytokens`, allowed in alert
     and enforce.
   - Decoys are created `O_EXCL|O_NOFOLLOW`.
   - What was planted is recorded in `honeytokens.json` next to the baseline:
     dev+ino, a content hash, and any directories created.
   - After a crash, the next start re-adopts its own stale decoys rather than
     treating them as real files.
   - Removal deletes a path only if it is still the planted inode *with the
     decoy content*, because inode numbers are reused. Created directories are
     cleaned up.
9. **Destructive demo/bench scripts and an unpinned installer.**
   - `scripts/bench/*` ran `rm -rf` as root and installed setuid shells.
   - `scripts/dev/proof.sh` installed a setuid shell.
   - `scripts/dev/sync.sh` rsynced the tree to the upstream author's
     `servertest` host.
   - `scripts/install.sh` was meant to be run as `curl | sudo bash` and
     installed `releases/latest` without pinning a version.

   *Fix:* all of these are removed. This fork is **built in-house from a
   pinned, reviewed commit** with `make gen-vmlinux bpf build && sudo make
   install`, and never downloads release artifacts.

## `phage-jail` is outside the config gate

`phage-jail` is a separate operator tool, and **nothing in this file gates
it**:
- `phage-jail lock` attaches an eBPF-LSM exec-lock to a running service for as
  long as the command runs.
- `phage-jail profile` writes seccomp/systemd drop-in files.

`make install` installs it alongside `phaged`. **Do not install it on a canary
host**, or remove `/usr/local/bin/phage-jail` after `make install`, unless you
mean to use it by hand.

## Known open items

- **The honeytoken kernel map is keyed on inode number only.** A file on
  another filesystem with the same inode number would also trip the decoy alert.
  This is an alert false-positive, not an action. Keying the map on (dev, ino)
  needs a `sensors.bpf.c` change, plus a userspace conversion from `st_dev` to
  the kernel's `dev_t` encoding. The objects compile here (clang, libbpf 1.3,
  vmlinux.h from `bpftool btf dump`), but this sandbox refuses BPF loads
  (EPERM), so the change could not be verified and was not made.
- **N1: the gate inspects the writer's view later, not the opened inode.**
  It resolves the path in the writer's root *when the event is handled*, so
  what it sees can differ from what was opened.
  - **Missed heal.** A writer with the right uid (root, or the file's owner)
    can open the host file, then over-mount its own view and create a private
    file at the same path. The gate then sees "a different file" and skips the
    heal, while the attacker's data sits in the host file through the fd it
    already holds. The alert still fires.
  - **Wrong heal.** The reverse trick (write a private copy, then unmount or
    remove it) can still cause a wrong heal, but since round 4 only for a
    writer whose uid is root (including container root without a userns
    remap) or the file's current owner. Since round 5 the uid is re-checked
    before staging, and a missing file is recreated only for a root writer's
    event. In her own directory, the owner can still race the rename after
    that check; this only restores her own file with her own snapshot
    content. An unprivileged non-owner is refused by the gate and again by
    Heal.

  Both disappear once the sensor records the dev+ino of the opened inode
  (`file->f_inode`), and the euid/fsuid, in-kernel. That needs a BPF change,
  and it is why self-heal should stay off (see the recommendation at the
  top).
- **N2: the sensor reports write-opens, not writes.** An event is an `open`
  with write intent. Data written later through an fd opened earlier, before
  the heal ran or after it, raises no new event and is never healed. The
  write-open itself is alerted. Closing this needs write-path or close-time
  hooks in-kernel.
- **Self-heal for a writer that has already exited** heals only for a root or
  current-owner uid, and then lets the host file's content decide. A host edit
  that scored below `contain`, followed by a high-scoring write-open from such
  a writer, is reverted along with the attacker's write (see the next item).
  Recording the opened inode and the euid/fsuid in-kernel would remove this.
- **Snapshots are fixed at startup.** A legitimate edit to a sentinel (one that
  scored below `contain`) is not folded into the snapshot. If a later write-open to
  the same file scores high, the heal restores the *startup* content and undoes
  the legitimate edit too; the edited version is kept as evidence. After
  editing sentinel files on a host with self-heal armed, restart phaged.
- **The other never-contain names are still matched by `comm`:** `systemd`,
  `init`, `login`, `getty`, `agetty`, `systemd-logind`, `dbus-daemon` and
  `systemd-journal`. A payload using one of these names avoids containment,
  though it is still alerted. Unlike sshd, these have no inode check yet.
- **N5: dropped custom decoys stay on disk.** A leftover honeytoken record is
  cleaned up only if its content hash matches a decoy this build plants (so a
  tampered record cannot get an arbitrary file deleted). A custom decoy that
  is later removed from the decoy list therefore stays on disk, with its
  record logged as "unknown content hash". Delete such files by hand. The
  built-in decoys are always cleaned up.
- **SELinux.** Copying `security.selinux` is tested where the xattr can be set.
  The restore was not run on an SELinux-enforcing host.
- **No end-to-end run.** The full daemon could not be started here, because
  loading the BPF programs fails in this sandbox. The startup and arming
  records are covered by unit tests, and the flag rules were checked against
  the built binary.
- **The ring-buffer drop counter was not load-tested.** `make bpf` compiles
  every object with the counter; a test reads the compiled object (the map's
  type and sizes, and that every program writing the ring buffer also
  references the counter), and the userspace read is run against a real
  per-CPU map created in the test (map creation works here; program loads get
  EPERM). The in-kernel increment on a failed reservation has never run.
  Verify on a real host by filling the ring buffer (e.g. `SIGSTOP` phaged for
  a few seconds under load) and watching `phage status` and the heartbeat.
- **Novelty, heartbeat and checkpoints were not run in the daemon.** They are
  driven through `App.handle` and the heartbeat/checkpoint functions in unit
  tests; `Run` itself (sink opening order, goroutine start) needs a host that
  can load the sensors.
- **The Wazuh content was not run on a Wazuh manager.** Its tests model the
  rule matching and run the heartbeat check; validate with `wazuh-logtest`
  (docs/wazuh.md) before relying on it.
- **Rebase cost.** This branch adds a sensor map, a reservation helper used by
  every sensor, an extra event field and a refactored event loop
  (`App.handle`). Each rebase onto upstream must re-check that every
  `bpf_ringbuf_reserve` in new upstream sensors goes through
  `reserve_event()` (the object test fails if one does not) and that upstream
  changes to the loop body land in `handle`.
- **Release workflow.** `.github/workflows/release.yml` from upstream is
  unchanged. It runs only when a tag is pushed, and nothing in this fork
  consumes its output; the fork's build is `make release` (above).
