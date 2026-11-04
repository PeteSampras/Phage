# Demo: self-healing — undo an attacker's persistence in milliseconds

A live run on the test server (kernel 7.0) showing Phage **undo** a tampered
credential file. An attacker backdoors `authorized_keys`; Phage detects the
malicious write and restores the known-good version a moment later, keeping the
attacker's version as evidence.

## How it works
With `mode: enforce` and `enforcement.self_heal: true` in the config file (the old `-heal` flag is now an error), the agent snapshots a small, high-value sentinel set at
startup — SSH `authorized_keys` (root and each home), `/etc/crontab`, `/etc/cron.d/*`,
`/etc/ld.so.preload`. The file sensor reports **write-opens** (an `open` with
write intent), not individual writes. When it raises a **malicious verdict**
(enforce) against one of them, the agent waits for the write to land, then
atomically restores the snapshot and moves whatever is at the path into a
quarantine store.

It heals **only files it snapshotted**, and **only on a verdict the engine judged
malicious**. A legitimate edit (an admin adding a key in a session) scores low
and does not trigger a heal itself. The snapshot is taken at startup and never
updated, so if a *later* malicious write-open to the same file does trigger a
heal, the file goes back to its startup content, undoing the admin's edit too.
Restart phaged after editing sentinels. The attacker's version is preserved as
evidence. The agent's own restore write is excluded, so it can't loop.

> **This fork recommends leaving `enforcement.self_heal` off for now.** A
> writer that over-mounts its own view after opening the host file can
> defeat the check below, and data written later through an fd opened earlier
> is never seen. Closing both needs the opened inode (dev+ino) captured
> in-kernel. See FORK.md. Alert-only (shadow) deployments are unaffected.

Because the agent runs as root and several sentinels live in directories a
user controls (`/home/*/.ssh`), every step is symlink-safe (this fork): paths
are opened with `openat2(RESOLVE_NO_SYMLINKS)` (or an `O_NOFOLLOW` walk on older
kernels); the restored copy is created `O_CREAT|O_EXCL|O_NOFOLLOW` under a
random name **beside the target, through the verified parent directory fd** (so
it gets the directory's default SELinux context; the snapshot's
`security.selinux` label is re-applied best effort), given the original
owner/group/mode with `fchown`/`fchmod`, and `renameat`-ed over the target.
Whatever the attacker left at the path — an oversized file, a symlink, a FIFO —
is never followed or read through but is replaced; the evidence copy is
truncated or records the symlink target. The heal is refused only if a path
component is a symlink, the parent directory was swapped since the snapshot,
the parent is owned by neither root nor the file's owner, or the target is now
a directory.

**Whose file was written?** The event's path is resolved in the *writer's* view
of the filesystem, which may not be the host's (a container, or `unshare -m`).
Comparing mount namespaces is the wrong test — `unshare -Urm sh -c 'echo k >>
~/.ssh/authorized_keys'` is in a new namespace but still writes the host inode.
So the agent resolves the path inside the writer's root (`/proc/<pid>/root`,
`openat2(RESOLVE_IN_ROOT|RESOLVE_NO_SYMLINKS)`) and heals when that is the host
file's dev+ino. If it is a *different* file (a container's private copy), the
host file is not touched and the alert notes the skip.

If the writer's view cannot be checked — it has exited, or it removed its
private copy — the agent heals **only if that writer could have written the
host file at all**: its real uid in the init namespace (from the kernel event)
must be 0 or the sentinel's owner. Otherwise an unprivileged user could write
and delete a private copy in its own namespace and make the agent revert an
admin's later edit of the host file, for example reinstating a revoked key.
When the fallback does heal, the host file's content decides: it is compared
with the snapshot and left alone if unchanged. The sensor does not capture
euid/fsuid for file events, so a setuid-root writer run by a user is not healed
by this fallback; it is still alerted.

A burst of write-open events costs at most one extra heal: an event that
arrives while a heal is running marks the file dirty and the heal runs once
more, so a write-open reported just after the restore read the file is not
lost. Every heal attempt
writes a `self_heal` audit record (`outcome` `healed` | `unchanged` |
`failed:<err>`, with `path` and `evidence`). This includes write-opens by a
process that is already contained. The quarantine directory is capped at 64 MiB
by default; the oldest evidence by modification time is pruned first, and each
prune is logged. Leftover `.stage-*` files from an older version are removed.

## The run (enforce + self-heal)
```
self-heal armed: 5 sentinel file(s) snapshotted

good authorized_keys:
  ssh-ed25519 AAAAC3LEGITIMATEadminkey admin@company

>>> ATTACK: a session-less process backdoors authorized_keys
CRITICAL score=1.00 comm="bash" interactive=false :: a program wrote a
    persistence/credential file class it has never written on this host
    (wrote /home/demo/.ssh/authorized_keys)
SELF-HEALED /home/demo/.ssh/authorized_keys
    (restored known-good; attacker version saved to /var/lib/phage/quarantine/...)

authorized_keys AFTER:
  ssh-ed25519 AAAAC3LEGITIMATEadminkey admin@company      <- attacker key gone

quarantined attacker version (evidence):
  ssh-ed25519 AAAAC3LEGITIMATEadminkey admin@company
  ssh-ed25519 AAAAATTACKERbackdoorkey evil@attacker       <- what they tried
```

The backdoor key was removed within a moment of being written, the legitimate key
untouched, and the attacker's attempt captured for the incident record.

## Notes & limits
- **Verdict-gated, snapshot-gated:** heals only a known-good sentinel on a
  malicious verdict — a legitimate key addition (low score) is left alone.
- **Brief exposure window:** the malicious content exists for the moment between
  the write and the restore; self-heal shrinks the window, it does not make the
  write atomic. Pair it with the alert/containment for the writer.
- **Snapshot is startup-time:** a legitimately-changed sentinel should be
  re-snapshotted (future: re-snapshot on a verified/session write).
- Quarantine lives under `/var/lib/phage/quarantine`.

See `internal/selfheal` and `respond`/`selfHeal` in `internal/agent/app`.
