# Demo: self-healing — undo an attacker's persistence in milliseconds

A live run on the test server (kernel 7.0) showing Phage **undo** a tampered
credential file. An attacker backdoors `authorized_keys`; Phage detects the
malicious write and restores the known-good version a moment later, keeping the
attacker's version as evidence.

## How it works
With `mode: enforce` and `enforcement.self_heal: true` (or `-heal`, which is refused outside enforce), the agent snapshots a small, high-value sentinel set at
startup — SSH `authorized_keys` (root and each home), `/etc/crontab`, `/etc/cron.d/*`,
`/etc/ld.so.preload`. When the file sensor raises a **malicious-write verdict**
(enforce) against one of them, the agent lets the write land, then atomically
restores the snapshot and moves what the attacker wrote into a quarantine store.

It is safe by construction: it heals **only files it snapshotted**, and **only on
a verdict the engine judged malicious** — a legitimate edit (an admin adding a
key in a session) scores low and is never reverted. Nothing is lost; the
attacker's version is preserved as evidence. The agent's own restore write is
excluded, so it can't loop.

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
