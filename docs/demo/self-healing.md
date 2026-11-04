# Demo: self-healing — undo an attacker's persistence in milliseconds

A live run on the test server (kernel 7.0) showing Phage **undo** a tampered
credential file. An attacker backdoors `authorized_keys`; Phage detects the
malicious write and restores the known-good version a moment later, keeping the
attacker's version as evidence.

## How it works
With `mode: enforce` and `enforcement.self_heal: true` in the config file (the old `-heal` flag is now an error), the agent snapshots a small, high-value sentinel set at
startup — SSH `authorized_keys` (root and each home), `/etc/crontab`, `/etc/cron.d/*`,
`/etc/ld.so.preload`. When the file sensor raises a **malicious-write verdict**
(enforce) against one of them, the agent lets the write land, then atomically
restores the snapshot and moves what the attacker wrote into a quarantine store.

It is safe by construction: it heals **only files it snapshotted**, and **only on
a verdict the engine judged malicious** — a legitimate edit (an admin adding a
key in a session) scores low and is never reverted. Nothing is lost; the
attacker's version is preserved as evidence. The agent's own restore write is
excluded, so it can't loop.

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
a directory. A burst of writes schedules one heal per file, and the quarantine
directory is capped (64 MiB by default; oldest evidence pruned and logged).

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
