# Demo: the agent survives an attacker with root (tamper-resistance)

A live run on the test server (kernel 7.0, BPF LSM active) showing that an
attacker — even one running as **root** — cannot kill the Phage agent to blind
it. This is the enforcement half of self-defense: detection says "someone is
attacking me"; this says "and they can't."

## How it works
With `mode: enforce` and `enforcement.self_protect: true` (or `-protect`, which is refused outside enforce), the agent loads a small eBPF-LSM object
(`selfprotect.bpf.o`) that hooks `lsm/task_kill` and **denies** a lethal/stop
signal (`SIGKILL`/`SIGTERM`/`SIGSTOP`/`SIGINT`/`SIGQUIT`) aimed at the agent —
returning `EPERM` from inside the kernel, below even root's `kill`.

### Safety (this project has a lockout scar — so this is deliberate)
The denial is inert unless self-protection is armed, and it **always allows** three
senders: the agent itself, its launcher (parent pid), and **pid 1 (systemd/init)**.
So `systemctl stop` (sent by pid 1) and a reboot always stop the agent — it can
never truly lock the box out. Detaching the program (the agent exiting) lifts all
protection. The LSM object is separate from the detection sensors, so a kernel
without BPF LSM simply runs the agent unprotected rather than failing to start.

## The run
```
self-protection ARMED: signals that would kill the agent are denied
    (except from pid 1 / launcher); systemctl stop and reboot still work
agent pid=11288

>>> ATTACK: a separate (non-launcher) process tries to SIGKILL the agent
kill DENIED: (11288) - Operation not permitted
=> agent SURVIVED the attacker's SIGKILL (tamper denied at the kernel)

>>> CONTROL: the legitimate launcher stops it — always allowed
stopped cleanly (protection lifts on exit)
```

The attacker's `kill -9` — issued as root — was refused by the kernel, and the
agent kept running; the legitimate launcher then stopped it normally. No reboot,
no lockout.

## What this is and isn't
- **Is:** the answer to the standard critique of eBPF security tools — *"root
  just disables them."* Here root cannot kill the agent; blinding it becomes loud
  and hard. Combined with the detection sensors (which flag the *attempt*) and the
  dead-man's-switch (which flags telemetry going silent), blinding Phage is
  expensive on every path.
- **Isn't:** absolute. A ring-0 attacker (malicious kernel module, or one who
  detaches the eBPF program or disables BPF LSM) is still above the agent. The
  honest claim is "survives an attacker with root userspace," not "unkillable."
- **Next:** write-protecting the agent's own binary, maps, and audit log
  (`lsm/file_open` / `bpf()` guards) and a watchdog restart round out full
  tamper-resistance. See [roadmap](../roadmap.md).

See `bpf/programs/selfprotect.bpf.c` and `internal/selfprotect`.
