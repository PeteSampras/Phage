# Quickstart

> ⚠️ Early but working. The daemon loads the eBPF sensors, learns a baseline,
> and scores/contains in alert and enforce modes, live-verified on a test server.
> This fork builds from source only. See [development](development.md).

## Requirements
- Linux, kernel ≥ 5.8 with BTF (`CONFIG_DEBUG_INFO_BTF=y`). Check:
  ```sh
  ls /sys/kernel/btf/vmlinux && echo "BTF present"
  ```
- Root (eBPF loading needs privileges).

## Install
This fork is built in-house from a pinned, reviewed commit — there is no
release download or `curl | sudo bash` installer (see [FORK.md](../../FORK.md)).
On the target (or a build host with the same architecture):
```sh
git checkout <reviewed-commit-sha>
make gen-vmlinux bpf build && sudo make install
sudo systemctl daemon-reload && sudo systemctl enable --now phage
```
The service then runs in **learn mode** — skip to
[Graduate to alert](#graduate-to-alert) once the baseline is mature, and use
`journalctl -u phage -f` to watch it. The manual steps below are for running
straight from a source tree instead.

## First run — always start in learn mode
```sh
sudo mkdir -p /etc/phage
sudo cp configs/phage.example.yaml /etc/phage/phage.yaml
# mode: learn   (do not change yet)
sudo phaged -config /etc/phage/phage.yaml
```
Path flags (`-state`, `-audit`, `-control`) override the file for that run.
`-mode` may only **lower** the file's mode (e.g. `-mode learn` over an alert
config); it can never raise it. Without `-config` the mode is learn, so
`-mode alert`/`-mode enforce` are refused — put the mode in the file. Host-modifying features can be enabled only in the config file.
Let it learn for at least a week (`learn_window`). It is building the baseline of
how your server normally behaves. It will not alert or act in this phase — that
is correct.

## Graduate to alert
Once the baseline is populated, set `mode: alert`, restart, and watch what it
flags:
```sh
phage events          # live anomalies with their reasons
```
Tune `thresholds.notify` until the signal is trustworthy.

## Graduate to enforce
Only when you trust the alerts, set `mode: enforce` **and** turn on the acting
features you want in the `enforcement:` block (all default off — with none on,
enforce only alerts):
```yaml
mode: enforce
enforcement:
  isolate: true    # network quarantine for egress/C2 verdicts
  freeze: true     # reversible cgroup freeze; release with `phage thaw <pid>`
```
Setting an `enforcement:` key in learn or alert mode is a startup error, and the
old `-heal`/`-protect`/`-honeytokens` flags are errors in every mode. Check
`/var/lib/phage/audit.jsonl`: each start writes a `startup` record saying what
armed. Nothing is ever killed.

See [modes](../concepts/modes.md) for why this ordering matters.
