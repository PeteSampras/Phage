# Demo: honeytokens fused into the kernel sensor

A live run on the test server (kernel 7.0) showing Phage catch an intruder the
instant they reach for credentials — with a decoy wired directly into the kernel
`open` path, not a cloud callback an attacker could block.

## How it works
With `deception.honeytokens: true` in the config file and `mode: alert` or `enforce` (the old `-honeytokens` flag is now an error; planting files is a host change, so it is opt-in and announced in the startup audit record), the agent plants a few decoy credential files in the
places an intruder greps for secrets — a fake `~/.aws/credentials`, a fake SSH
key, a fake `.pgpass` — each with obviously-inert content, and **only where no
real file already exists** (a honeytoken never clobbers a real credential). It
registers their inode numbers with the kernel sensor; any **open** of one — read
or write — is reported. Nothing legitimate references these files, so a read is a
near-zero-false-positive sign of snooping. It is scored directly (not through the
learned baseline), so it fires on an empty baseline.

## The run (alert mode)
```
honeytokens planted: 3 decoys — any read of one is a high-confidence alert

>>> CONTROL: a normal file read (not a decoy)
   (no alert — correct)

>>> ATTACK: an intruder reads the decoy
CRITICAL score=1.00 comm="cat" :: read a planted honeytoken decoy
    "/root/.aws/credentials" — near-certain credential theft / intruder snooping
```

The normal read was silent; reading the decoy fired **CRITICAL**, naming the file
and the reading process. The decoys are removed when the agent stops.

## Why this is strong
Canarytokens and similar are external and round-trip an alert to a cloud service —
which an attacker on the host can block, and which the attacker's own process
never has to touch. Here the tripwire is *inside the kernel sensor and wired to
the response engine*: the read is caught at the `open`, attributed to the process,
and can drive containment in enforce mode — no network dependency. Honeytokens
are the single highest signal-to-noise detector you can add, because a decoy read
has essentially no benign explanation.

## Notes
- The agent (`phaged`) is excluded — it plants the decoys, it does not trip them.
- Legitimate blanket readers (a backup job, an AV scanner) would also read a decoy;
  place decoys where only snooping reaches, and exclude such tools if needed.
- Enforce mode freezes the reader (subject to the `containmentSafe` guardrails).

See the honeytoken map and read check in `bpf/programs/sensors.bpf.c`, the decoy
seeder in `internal/honeytoken`, and `respondHoneytoken` in `internal/agent/app`.
