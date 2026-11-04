# About this fork

This is a hardened fork of [Phage](https://github.com/AzozzALFiras/Phage), based
on upstream commit `9757354`. It keeps all of upstream's enforcement code
(isolate, freeze, network quarantine, self-heal, self-protect, honeytokens,
`phage-jail`) so that it is still available. The difference is that **nothing
that acts on the host arms unless the operator turns it on in the config
file.** Out of the box the fork learns, then alerts.

Upstream's MIT `LICENSE` and copyright notice are unchanged. This file and the
commits on top of `9757354` record what changed.

## Default posture

| Mode | What it does |
|---|---|
| `learn` (default) | builds the baseline; no alerts, no actions |
| `alert` | scores and alerts; no actions |
| `enforce` | scores and alerts, and acts **only through the features enabled in `enforcement:`** |

All five acting features are **off by default**. If none are on, `enforce`
behaves exactly like `alert`.

| `enforcement:` key | Acts by | Upstream armed it when |
|---|---|---|
| `isolate` | cutting a process's egress (eBPF cgroup network quarantine) | in any `mode: enforce` |
| `freeze` | freezing the process tree with the cgroup freezer | in any `mode: enforce` |
| `self_heal` | rewriting sentinel files (`authorized_keys`, cron, `ld.so.preload`) | `-heal` was given, **in any mode** |
| `self_protect` | an eBPF-LSM program that refuses signals sent to the agent | `-protect` was given, **in any mode** |
| `honeytokens` | creating decoy credential files | `-honeytokens` was given, **in any mode** |

## Turning enforcement on

In `/etc/phage/phage.yaml`:

```yaml
mode: enforce
enforcement:
  isolate: true
  freeze: false
  self_heal: true
  self_protect: false
  honeytokens: false
release_after: 300   # seconds of quiet before an isolated process is released
```

Then run `systemctl restart phage`. The rules:

- A feature arms only when `mode: enforce` **and** its own key is `true`.
- Phaged **refuses to start** if a feature is `true` while the mode is `learn`
  or `alert`. This applies to the YAML keys and to the old
  `-heal` / `-protect` / `-honeytokens` flags, which still exist as overrides
  for those keys. It fails closed with an error that names the features
  involved.
- If the matrix asks for a containment rung that is not armed, the agent sends
  an alert instead, and the reason gets a suffix such as
  `[freeze not armed: alert only]`. If `isolate` is on but its eBPF program
  fails to load, the agent falls back to freeze, but only when `freeze` is also
  armed. The agent never kills.
- Arming is loud. On startup phaged logs one line:
  ```
  ENFORCEMENT ARMED event=enforcement_armed mode=enforce features=isolate,self_heal failed=none pid=1234
  ```
  It also appends an audit record with `"kind":"enforcement_armed"`, listing
  `features` (what armed) and `failed` (what was requested but could not arm,
  e.g. `self_protect` on a kernel without BPF LSM). Point your SIEM at it. If
  nothing arms, the journal says so instead. Response records now carry
  `"kind":"response"`.

## What changed and why

These findings come from a read-only security review of `9757354`. Each one is
fixed in its own commit.

1. **HIGH: self-heal ran in alert mode.** `-heal` armed it in any mode, and the
   restore fired without checking the mode. This contradicted the package doc
   and the flag's help text, both of which said "enforce". *Fix:* acting
   features are now gated on `mode: enforce` plus their own key (see above).
   Docs and help text are corrected.
2. **HIGH: self-heal could be steered into writing arbitrary files as root.**
   The restore wrote `path + ".phage-heal"` with `os.WriteFile`, which follows
   symlinks and truncates the target, and then renamed it into place. Watched
   files include `/home/*/.ssh/authorized_keys`, which sit in directories the
   user owns. A local user could therefore make root overwrite
   `/etc/shadow` or `/root/.ssh/authorized_keys`. Snapshots also followed
   symlinks, and the original owner was lost. *Fix:* every path is resolved
   with `openat2(RESOLVE_NO_SYMLINKS)`, or with an `O_NOFOLLOW` walk on kernels
   without openat2. After that, all work goes through file descriptors:
   - The parent directory must be owned by root or by the file's owner. It
     must also have the same dev/inode it had at snapshot time.
   - The target must be a regular file. If it has been replaced by a symlink,
     the heal is refused rather than followed.
   - The restored copy is created with `O_CREAT|O_EXCL|O_NOFOLLOW` in the
     root-only 0700 quarantine directory. It is given the original uid, gid and
     mode with `fchown`/`fchmod`, fsynced, and then `renameat`-ed into the
     verified parent directory. If the target is on another filesystem, the
     copy is staged the same way next to the target instead.
   - Evidence copies are also created with `O_EXCL|O_NOFOLLOW`.
3. **MEDIUM: trust was based on `comm`, which the attacker controls.** The
   agent ignored file writes and honeytoken reads from any process named
   `phaged`. It treated lethal signals from `systemd`/`init` as a supervisor
   stop, and it never froze anything named (or parented by) `sshd`. *Fix:*
   - The agent recognises itself by its own tgid.
   - Only pid 1, or the launcher pid recorded at startup, counts as the
     supervisor.
   - sshd is recognised by `/proc/<pid>/exe` resolving to an OpenSSH server
     binary. This includes the OpenSSH ≥ 9.8 `sshd-session` / `sshd-auth`
     binaries, and a binary marked `(deleted)` after a package upgrade.
4. **`-protect` and `-honeytokens` armed in any mode.** These flags, and
   `-heal`, existed only on the command line. Because the YAML loader rejects
   unknown keys, there was no way to set them in the config file. *Fix:* they
   are now `enforcement:` keys, gated as above. `release_after` is now a YAML
   key too.
5. **LOW: control socket.** The socket was created with the process umask and
   chmod'ed to 0600 after `Listen`, and peers were never checked, even though
   `phage thaw` releases a contained process. *Fix:* the socket is bound under
   umask 077, and `SO_PEERCRED` must report uid 0. Connections also get a
   deadline.
6. **MEDIUM: journal line forging.** The verdict log printed the reason, which
   contains attacker-chosen file paths and executable names, with `%s`. *Fix:*
   attacker-influenced strings are printed with `%q` (`reason="..."`), and
   `phage events` quotes them too.
7. **Destructive demo/bench scripts and an unpinned installer.**
   - `scripts/bench/*` ran `rm -rf` as root and installed setuid shells.
   - `scripts/dev/proof.sh` installed a setuid shell.
   - `scripts/dev/sync.sh` rsynced the tree to the upstream author's
     `servertest` host.
   - `scripts/install.sh` was meant to be run as `curl | sudo bash` and
     installed `releases/latest` without pinning a version.

   *Fix:* `scripts/dev`, `scripts/bench` and `scripts/install.sh` are removed.
   This fork is **built in-house from a pinned, reviewed commit** with
   `make gen-vmlinux bpf build && sudo make install`, and never downloads
   release artifacts. Docs that cited the removed harnesses keep upstream's
   published results, with a note.

The fork also makes one small related fix. Honeytoken decoys are now created
with `O_EXCL|O_NOFOLLOW`. Upstream checked with `Stat` and then called
`WriteFile`, which follows a dangling symlink.

## Known residuals

- The other never-freeze names (`systemd`, `init`, `login`, `getty`,
  `agetty`, `systemd-logind`, `dbus-daemon`, `systemd-journal`) are still
  matched by `comm`. A payload with one of these names can still avoid a
  freeze, though it will still raise an alert. Matching them by executable
  path would need per-distro path lists, and a wrong list would risk freezing
  the real process and locking the operator out, so this was left alone on
  purpose. It only matters when `freeze` is armed.
- `.github/workflows/release.yml` from upstream is unchanged. It runs only when
  a tag is pushed, and nothing in this fork consumes its output.
- The fallback that stages a heal next to the target (used when the target
  is on another filesystem) is covered by code review only. The tests stage
  inside a single filesystem.
