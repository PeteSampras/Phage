# Phage in Wazuh

`deploy/wazuh/` makes Phage observable as a SOC sensor: the manager gets a decoder and rules,
each Phage host's agent gets two log files and two checks. Nothing here changes what Phage does
on the host; alert-only stays the default.

| File | Goes to | What it is |
|---|---|---|
| `phage_rules.xml` | manager, `/var/ossec/etc/rules/` | rules 100800-100849 (needs Wazuh 4.3+, for PCRE2) |
| `phage_decoders.xml` | manager, `/var/ossec/etc/decoders/` | field names for the two checks (optional; see below) |
| `agent_ossec.conf` | agent, inside `<ossec_config>` | the two JSON files and the two command checks |
| `phage-heartbeat-check` | agent host, `/usr/local/lib/phage/` | prints the age of the last heartbeat |

```sh
# manager
install -m 0640 -g wazuh deploy/wazuh/phage_rules.xml    /var/ossec/etc/rules/
install -m 0640 -g wazuh deploy/wazuh/phage_decoders.xml /var/ossec/etc/decoders/
systemctl restart wazuh-manager
# each Phage host
install -m 0755 deploy/wazuh/phage-heartbeat-check /usr/local/lib/phage/
# paste deploy/wazuh/agent_ossec.conf into /var/ossec/etc/ossec.conf, then
systemctl restart wazuh-agent
```

## What Phage writes

**The audit trail**, `/var/lib/phage/audit.jsonl` (JSON lines, 0600 root), one record per:

| `kind` | When |
|---|---|
| `startup` | every start: `status` (`none` / `armed` / `failed`), mode, features, config and baseline sha256, novelty path and TLP |
| `enforcement_armed` | a start that armed a host-modifying feature |
| `disarmed` | a start with a `-mode` downgrade that switched features off |
| `response` | a verdict at or above `thresholds.notify`, an attack on the agent, or a decoy read: `requested`, `action`, `outcome`, `score` |
| `self_heal` | a self-heal attempt (`enforcement.self_heal` only): `healed` / `unchanged` / `failed:<err>` |
| `heartbeat` | every `output.heartbeat_interval` seconds (default 60), in every mode: `health.{events, events_per_sec, drops, drops_total, drops_error, enrich_lag_ms_avg, enrich_lag_ms_max, novelty_rows, novelty_suppressed, novelty_errors, baseline_overflow, checkpoint_errors}`, mode, armed features, `baseline_sha256` |

`health.drops` counts events the kernel sensors saw but could not queue for phaged (the ring
buffer was full) during the interval. Any drop means detection was incomplete.

**The novelty file**, `/var/lib/phage/novelty.jsonl` (alert and enforce mode only), one row in
homelab-next's `novelty_finding` shape per verdict at or above `thresholds.notify` (`finding`,
with `score`) and per event whose feature class was never seen while learning (`unlearned`, no
score). Every row is `source_kind: heuristic`: advisory, never a basis to act alone. A finding
row repeats a `response` record, so its rule stays at level 3; an `unlearned` row has no
response record and alerts at level 6. Getting rows into the lake's `novelty_finding` table is a
separate step: they must be written by the lake's own writer under Phage's source (homelab-next
ADR-0036 decision 6); Wazuh only carries them.

## The rules

| Rule | Level | Fires on |
|---|---|---|
| 100800 | 0 | any audit record (parent) |
| 100801 | 3 | startup, nothing armed |
| 100802 | 10 | startup with host-modifying features armed |
| 100803 | 8 | startup, features requested but none armed |
| 100804 | 12 | three startups within 10 minutes on one agent (crash loop) |
| 100805 | 10 | `enforcement_armed` |
| 100806 | 9 | `disarmed` |
| 100810 | 8 | a response |
| 100811 | 12 | a response that contained a process |
| 100812 | 10 | a response whose actuation failed |
| 100813 | 11 | a response with score 0.8 or more |
| 100815 / 100816 / 100817 | 10 / 10 / 3 | self-heal healed / failed / unchanged |
| 100820 | 0 | a heartbeat (parent) |
| 100821 | 10 | a heartbeat with ring-buffer drops |
| 100822 | 9 | a heartbeat with novelty rows that could not be written |
| 100823 | 7 | the drop counter cannot be read (an old eBPF object); repeats at most hourly |
| 100824 | 7 | baseline checkpoints have failed; repeats at most hourly |
| 100830 | 0 | a novelty row (parent) |
| 100831 | 3 | a novelty finding |
| 100832 | 6 | a novelty `unlearned` row |
| 100840 | 12 | no heartbeat for three intervals (agent-side check) |
| 100841 | 12 | `phage.service` is not active (agent-side check) |

## Silence needs an agent-side check

Wazuh rules are evaluated when an event arrives. No rule fires because an event did not arrive:
`frequency` with `timeframe` fires when at least that many matching events arrive within the
window, never when fewer do, and nothing else in the rule language counts an absence. So "the
heartbeat stopped" cannot be a manager rule over the audit trail.

The absence is turned into an event on the host instead. The agent runs `phage-heartbeat-check
180` every 60 seconds (a `command` localfile). It finds the last `heartbeat` record in the audit
trail and prints exactly one line: `status=fresh age=<s> max=180`, `status=stale age=<s>
max=180`, or `status=missing reason=<why>` (no trail, no heartbeat in it, a time it cannot
parse). Rule 100840 fires on `stale` and `missing`. 180 is three intervals of the default
`output.heartbeat_interval: 60`; scale it with the interval. The check is read-only and needs
GNU `date` and `tac`, and read access to the 0600 root trail (the agent's logcollector runs as
root).

Rule 100841 checks the service the same way, with `systemctl is-active phage.service`: any
answer but `active` fires it, including `activating`, which is what a crash loop looks like
between restarts. Rule 100804 is the other side of a crash loop: it counts `startup` records,
which is what `frequency` can do.

These checks cover phaged stopping, wedging, or failing to write its trail. They do not cover
the Wazuh agent itself stopping; Wazuh's own agent-disconnected alert covers that.

Commands in a centralized `agent.conf` (rather than the agent's own `ossec.conf`) run only with
`logcollector.remote_commands=1` in the agent's `local_internal_options.conf`.

## Field names Wazuh may claim

`status` and `action` (and `id`, `url`, `data`, `srcip` and a few more) are Wazuh static field
names: the JSON decoder may store those keys as static fields, which `<field name="...">` does
not match. So no rule depends on them. A startup record's status is read from the end of its
`reason` (`phaged started: mode=alert status=armed`), and a novelty row is a finding when it has
a `score` and unlearned when its `message` ends with `(unlearned)`. Phage's tests hold both
formats.

## Why the decoder file is nearly empty

Wazuh's built-in `json` decoder already decodes both JSON files; nested objects flatten to dotted
names such as `health.drops`. A second root decoder for JSON lines would never be reached, since
root decoders are tried in load order and the built-in one comes first. The rules therefore match
`decoded_as json` plus Phage's own field values (`kind`, `pid`, `reason` for the trail;
`source_kind: heuristic` and a `phage-` uid for novelty rows). `phage_decoders.xml` only names
the fields of the two command checks (`phage_check`, `phage_status`) for searching; the rules
match those lines directly and do not need it.

## Testing

`go test ./deploy/wazuh/` builds records with Phage's own code and runs them through a model of
the rules (root rule, first matching child, deepest wins), with Go's regexp standing in for PCRE2
(the patterns stay in the common subset). It also runs `phage-heartbeat-check` against fresh,
stale, missing and forged trails, and checks that the files are well-formed and name no address.

**None of this has been run on a Wazuh manager.** Before relying on it, load the files on a
manager and feed `/var/ossec/bin/wazuh-logtest` one line of each kind, for example:

```
{"time":"2026-11-04T10:00:00Z","kind":"startup","action":"startup","score":0,"pid":4000,"comm":"phaged","reason":"phaged started: mode=alert status=armed","status":"armed","mode":"alert"}
{"time":"2026-11-04T10:01:00Z","kind":"heartbeat","action":"heartbeat","score":0,"pid":4000,"comm":"phaged","reason":"heartbeat: 3.10 events/s, 12 drop(s)","mode":"alert","health":{"interval_seconds":60,"events":186,"events_per_sec":3.1,"drops":12,"drops_total":12,"drops_error":"","enrich_lag_ms_avg":0.4,"enrich_lag_ms_max":2.1,"novelty_rows":0,"novelty_suppressed":0,"novelty_errors":0,"baseline_overflow":0,"checkpoint_errors":0}}
{"uid":"phage-0123456789abcdef0123456789abcdef01234567","time":"2026-11-04T10:02:00.000000Z","as_of":"2026-11-04T10:02:00.004000Z","source":"phage-host","source_kind":"heuristic","profile":"connect","entity_kind":"host","entity":"web01","value":"192.0.2.7:4444","status":"unlearned","support":0,"entity_total":0,"count":1,"message":"web01: connect 192.0.2.7:4444 by sh (pid 4242): this kind of event was never seen while learning, so it is not scored (unlearned)","reasons":["no observations in the baseline for net.egress_comm_id"],"tlp":"amber"}
```

Expect 100802, 100821 and 100832. For the checks, `wazuh-logtest` takes the raw command line
(`ossec: output: 'phage-heartbeat': status=stale age=412 max=180`, expect 100840). If a field
rule does not match on your version, check how `wazuh-logtest` names the decoded field first.
