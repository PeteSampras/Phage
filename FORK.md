# About this fork

This is a hardened fork of [Phage](https://github.com/AzozzALFiras/Phage), based
on upstream commit `9757354`. It keeps all of upstream's enforcement code
(isolate, freeze, network quarantine, self-heal, self-protect, honeytokens,
`phage-jail`) so that it is still available. The difference is that **nothing
that changes the host arms unless the operator turns it on explicitly in the
config file.** Out of the box the fork learns, then alerts.

Upstream's MIT `LICENSE` and copyright notice are unchanged. The commits on top
of `9757354` record every change.

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

  `phage events` shows the same fields. A write by a process that is already
  contained still gets a response record, with `outcome: already_contained`.
- **Self-heal records** (`kind: self_heal`), one per heal attempt: `outcome`
  is `healed`, `unchanged` or `failed:<err>`, along with the `path`, the
  `evidence` location, and the writer's pid and comm.
- **Failing to write a startup, arming or disarm record is fatal.** A failed
  response or self-heal record during the run is only logged.

## What stops phaged from starting (monitor it)

phaged fails closed at startup. Under `Restart=on-failure` (every 5 s) any of
the following becomes a crash loop that leaves the host **unmonitored**:
- a full or read-only `/var`: the audit trail cannot be opened, or the startup
  or arming record cannot be written;
- a config file that does not load: YAML errors, unknown keys, non-literal
  booleans, an invalid combination, or a missing file;
- a removed flag (`-heal`, `-protect`, `-honeytokens`) left in a drop-in;
- a `-mode` that would raise the file's mode.

Alert on it: watch `systemctl show -p NRestarts,ActiveState phage` (or the
node-exporter systemd collector), or add an `OnFailure=` unit that pages, and
alert on disk space for `/var/lib/phage`.

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
   - The quarantine directory is capped at 64 MiB. The oldest evidence is
     pruned first, and each prune is logged.
3. **Self-heal triggered by writes in another mount namespace.** A container
   writing its own `/root/.ssh/authorized_keys` produced the same path as the
   host's file. A mount-namespace comparison (the first fix) was wrong in the
   other direction: `unshare -Urm sh -c 'echo k >> ~/.ssh/authorized_keys'`
   is in a new namespace but still writes the host inode, so it was alerted
   and never healed. *Fix:* the path is resolved inside the writer's root
   (`/proc/<pid>/root`, `openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS)`).
   - If that is the host file's dev+ino, the heal runs.
   - If it is a different file (the container's own copy), the host file is
     not touched, and the response reason records the skip.
   - If the writer has exited or its view cannot be read, the heal runs and
     the host file's own content decides: Heal compares the file with its
     snapshot and does nothing if it is unchanged, which is the case when a
     container wrote only its private copy.

   Writes that arrive during a running heal set a dirty bit, so the heal runs
   once more rather than missing them. Every heal attempt is audited.
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
- **Self-heal for a writer that has already exited relies on content.** If the
  writer has gone (for example `cat >> file`), its view of the path cannot be
  checked, so the heal runs whenever the host file differs from its snapshot.
  A container's private write cannot change the host file, so it is not
  reverted. But a host edit that scored below `contain`, followed by a
  high-scoring write from a writer that has already exited, is reverted along
  with the attacker's write (see the next item). Recording the written inode
  in-kernel would remove this, but needs a BPF change, which was not made for
  the same reason.
- **Snapshots are fixed at startup.** A legitimate edit to a sentinel (one that
  scored below `contain`) is not folded into the snapshot. If a later write to
  the same file scores high, the heal restores the *startup* content and undoes
  the legitimate edit too; the edited version is kept as evidence. After
  editing sentinel files on a host with self-heal armed, restart phaged.
- **The other never-contain names are still matched by `comm`:** `systemd`,
  `init`, `login`, `getty`, `agetty`, `systemd-logind`, `dbus-daemon` and
  `systemd-journal`. A payload using one of these names avoids containment,
  though it is still alerted. Unlike sshd, these have no inode check yet.
- **SELinux.** Copying `security.selinux` is tested where the xattr can be set.
  The restore was not run on an SELinux-enforcing host.
- **No end-to-end run.** The full daemon could not be started here, because
  loading the BPF programs fails in this sandbox. The startup and arming
  records are covered by unit tests, and the flag rules were checked against
  the built binary.
- **Release workflow.** `.github/workflows/release.yml` from upstream is
  unchanged. It runs only when a tag is pushed, and nothing in this fork
  consumes its output.
