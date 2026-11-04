// Package wazuh holds no code: these tests check the Wazuh decoder, rules and
// agent snippet in this directory against records produced by Phage's own
// code. They evaluate the rules with a small model of Wazuh's matching (root
// rule, then the first matching child, deepest wins), with Go's regexp
// standing in for PCRE2, so the patterns are kept to the common subset. They
// do not run Wazuh: validate on a manager with wazuh-logtest (docs/wazuh.md).
package wazuh

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/novelty"
)

type pattern struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type rule struct {
	ID             string    `xml:"id,attr"`
	Level          int       `xml:"level,attr"`
	Frequency      int       `xml:"frequency,attr"`
	IfSid          string    `xml:"if_sid"`
	IfMatchedGroup string    `xml:"if_matched_group"`
	DecodedAs      string    `xml:"decoded_as"`
	Location       string    `xml:"location"`
	Match          string    `xml:"match"`
	Regex          *pattern  `xml:"regex"`
	Fields         []pattern `xml:"field"`
	Description    string    `xml:"description"`
	Group          string    `xml:"group"`
}

type ruleFile struct {
	Name  string `xml:"name,attr"`
	Rules []rule `xml:"rule"`
}

func loadRules(t *testing.T) []rule {
	t.Helper()
	b, err := os.ReadFile("phage_rules.xml")
	if err != nil {
		t.Fatal(err)
	}
	var f ruleFile
	if err := xml.Unmarshal(b, &f); err != nil {
		t.Fatalf("phage_rules.xml: %v", err)
	}
	return f.Rules
}

// staticFields are keys Wazuh's JSON decoder may store as static fields,
// invisible to <field name=...>. The model hides them, so a rule that relied
// on one fails here.
var staticFields = map[string]bool{"status": true, "action": true, "id": true, "url": true, "data": true,
	"srcip": true, "dstip": true, "srcport": true, "dstport": true, "protocol": true, "srcuser": true,
	"dstuser": true, "user": true, "command": true, "system_name": true, "extra_data": true}

// flatten turns a JSON line into Wazuh-style dynamic fields: nested objects
// flatten to dotted names, numbers keep their JSON text.
func flatten(t *testing.T, line []byte) map[string]string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("not JSON: %s", line)
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, sub := range x {
				name := k
				if prefix != "" {
					name = prefix + "." + k
				}
				walk(name, sub)
			}
		case string:
			out[prefix] = x
		case json.Number:
			out[prefix] = x.String()
		case bool:
			out[prefix] = strconv.FormatBool(x)
		case []any:
			b, _ := json.Marshal(x)
			out[prefix] = string(b)
		}
	}
	walk("", m)
	for k := range staticFields {
		delete(out, k)
	}
	return out
}

func re(t *testing.T, p pattern) *regexp.Regexp {
	t.Helper()
	if p.Type != "pcre2" {
		t.Fatalf("pattern %q is not type=pcre2: the rules use PCRE2 throughout", p.Value)
	}
	r, err := regexp.Compile(p.Value)
	if err != nil {
		t.Fatalf("pattern %q is outside the PCRE2/RE2 common subset: %v", p.Value, err)
	}
	return r
}

func matches(t *testing.T, r rule, fields map[string]string, line, location string, isJSON bool) bool {
	if r.DecodedAs != "" && (r.DecodedAs != "json" || !isJSON) {
		return false
	}
	if r.Location != "" && !osMatch(r.Location, location) {
		return false
	}
	for _, f := range r.Fields {
		v, ok := fields[f.Name]
		if !ok || !re(t, f).MatchString(v) {
			return false
		}
	}
	if r.Match != "" {
		// OS_Match: a leading ^ anchors; the rest is literal.
		if strings.HasPrefix(r.Match, "^") {
			if !strings.HasPrefix(line, r.Match[1:]) {
				return false
			}
		} else if !strings.Contains(line, r.Match) {
			return false
		}
	}
	if r.Regex != nil && !re(t, *r.Regex).MatchString(line) {
		return false
	}
	return true
}

// osMatch models Wazuh's OS_Match: `|` separates alternatives, a leading
// `^` anchors one at the start and a trailing `$` at the end; the rest is a
// literal (case-insensitive in Wazuh; the paths here are lower case).
func osMatch(pattern, s string) bool {
	for _, alt := range strings.Split(pattern, "|") {
		start, end := strings.HasPrefix(alt, "^"), strings.HasSuffix(alt, "$")
		lit := strings.TrimSuffix(strings.TrimPrefix(alt, "^"), "$")
		switch {
		case start && end && s == lit,
			start && !end && strings.HasPrefix(s, lit),
			!start && end && strings.HasSuffix(s, lit),
			!start && !end && strings.Contains(s, lit):
			return true
		}
	}
	return false
}

// fire returns the rule that would fire for an event: the first matching root
// rule, then repeatedly the first matching child. Rule 530 (Wazuh's own
// "ossec: output:" rule) is modelled for command output.
func fire(t *testing.T, rules []rule, line string) string {
	t.Helper()
	loc := "(web01) any->/var/lib/phage/audit.jsonl"
	if strings.Contains(line, `"source_kind"`) {
		loc = "(web01) any->/var/lib/phage/novelty.jsonl"
	}
	return fireAt(t, rules, line, loc)
}

// fireAt is fire for an event read from location (as Wazuh names it).
func fireAt(t *testing.T, rules []rule, line, location string) string {
	t.Helper()
	isJSON := strings.HasPrefix(line, "{")
	var fields map[string]string
	if isJSON {
		fields = flatten(t, []byte(line))
	}
	cur := ""
	if !isJSON && strings.HasPrefix(line, "ossec: output: ") {
		cur = "530"
	}
	if cur == "" {
		for _, r := range rules {
			if r.IfSid == "" && r.IfMatchedGroup == "" && matches(t, r, fields, line, location, isJSON) {
				cur = r.ID
				break
			}
		}
	}
	for cur != "" {
		next := ""
		for _, r := range rules {
			if r.IfSid == cur && matches(t, r, fields, line, location, isJSON) {
				next = r.ID
				break
			}
		}
		if next == "" {
			break
		}
		cur = next
	}
	return cur
}

func line(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func base() audit.Entry {
	return audit.Entry{Time: time.Now(), PID: 4000, Comm: "phaged", Mode: "alert", Version: "v1"}
}

// startup builds a startup record as phaged does (internal/agent/app
// announceStartup; TestStartupReasonEndsWithStatus there holds the format).
func startup(status string) audit.Entry {
	e := base()
	e.Kind, e.Action, e.Status = audit.KindStartup, audit.KindStartup, status
	e.Reason = "phaged started: mode=alert status=" + status
	return e
}

func response(outcome string, score float64) audit.Entry {
	e := base()
	e.Kind, e.Action, e.Requested, e.Outcome, e.Score = audit.KindResponse, "notify", "notify", outcome, score
	e.PID, e.Comm, e.Reason = 4242, "sh", "an outbound connection from a program that has never egressed (-> 192.0.2.7:4444)"
	return e
}

func heartbeat(h audit.Health) audit.Entry {
	e := base()
	e.Kind, e.Action, e.Health, e.BaselineSHA256 = audit.KindHeartbeat, audit.KindHeartbeat, &h, "none"
	e.Reason = "heartbeat: 1.00 events/s, 0 drop(s)"
	return e
}

func TestRulesFireOnPhageRecords(t *testing.T) {
	rules := loadRules(t)
	id := novelty.Identity{Source: "phage-host", EntityKind: "host", Entity: "web01", TLP: "amber", Bucket: time.Hour}
	ev := model.Event{Time: time.Now(), Kind: kind.Connect, PID: 4242, Comm: "sh", Net: model.NetConn{DestIP: "192.0.2.7", DestPort: 4444}}
	v := verdict.Verdict{Score: 0.62, Reasons: []verdict.Reason{{Feature: "net.egress_comm_id", Contribution: 0.62, Detail: "never egressed", Confidence: 1, Samples: 40}}}
	high := v
	high.Score = 0.93
	selfHeal := func(outcome string) audit.Entry {
		e := base()
		e.Kind, e.Action, e.Outcome, e.Path = audit.KindSelfHeal, audit.KindSelfHeal, outcome, "/root/.ssh/authorized_keys"
		e.Reason = "self-heal of /root/.ssh/authorized_keys after a malicious write: " + outcome
		return e
	}
	armed := base()
	armed.Kind, armed.Action, armed.Status, armed.Features = audit.KindEnforcementArmed, audit.KindEnforcementArmed, "armed", []string{"freeze"}
	armed.Reason = "host-modifying features armed: freeze; requested but not armed: none"
	disarmed := base()
	disarmed.Kind, disarmed.Action, disarmed.Disarmed = audit.KindDisarmed, audit.KindDisarmed, []string{"freeze"}
	disarmed.Reason = "-mode alert over a enforce config switched off: freeze"

	for name, c := range map[string]struct {
		line string
		want string
	}{
		"startup none":        {line(t, startup("none")), "100801"},
		"startup armed":       {line(t, startup("armed")), "100802"},
		"startup failed":      {line(t, startup("failed")), "100803"},
		"enforcement armed":   {line(t, armed), "100805"},
		"disarmed":            {line(t, disarmed), "100806"},
		"response notified":   {line(t, response("notified", 0.55)), "100810"},
		"response skipped":    {line(t, response("skipped:freeze not armed: alert only", 0.6)), "100810"},
		"response high":       {line(t, response("notified", 0.93)), "100813"},
		"response score 1":    {line(t, response("notified", 1)), "100813"},
		"response contained":  {line(t, response("contained", 0.95)), "100811"},
		"response failed":     {line(t, response("failed:freeze: EBUSY", 0.95)), "100812"},
		"self-heal healed":    {line(t, selfHeal("healed")), "100815"},
		"self-heal failed":    {line(t, selfHeal("failed:unsafe path")), "100816"},
		"self-heal unchanged": {line(t, selfHeal("unchanged")), "100817"},
		"heartbeat healthy":   {line(t, heartbeat(audit.Health{Events: 60, EventsPerSec: 1})), "100820"},
		"heartbeat 10 events": {line(t, heartbeat(audit.Health{Events: 10})), "100820"},
		"heartbeat drops":     {line(t, heartbeat(audit.Health{Drops: 12, DropsTotal: 40})), "100821"},
		"heartbeat 10 drops":  {line(t, heartbeat(audit.Health{Drops: 10})), "100821"},
		"novelty errors":      {line(t, heartbeat(audit.Health{NoveltyErrors: 3})), "100822"},
		"drops unreadable":    {line(t, heartbeat(audit.Health{DropsError: "sensor object has no phage_drops map"})), "100823"},
		"checkpoint errors":   {line(t, heartbeat(audit.Health{CheckpointErrors: 1})), "100824"},
		"novelty finding":     {line(t, id.Finding(ev, v, "none", time.Now())), "100831"},
		"novelty high":        {line(t, id.Finding(ev, high, "none", time.Now())), "100831"},
		"novelty unlearned":   {line(t, id.Unlearned(ev, []string{"net.egress_comm_id"}, "none", time.Now())), "100832"},
		"novelty burst":       {line(t, id.Burst(id.Unlearned(ev, nil, "none", time.Now()), 21, time.Now())), "100833"},
		"heartbeat idle":      {line(t, heartbeat(audit.Health{Events: 0})), "100825"},
		"idle with drops":     {line(t, heartbeat(audit.Health{Events: 0, Drops: 4})), "100821"},
		"heartbeat skew":      {"ossec: output: 'phage-heartbeat': status=skew age=-900 max=180", "100840"},
		"heartbeat stale":     {"ossec: output: 'phage-heartbeat': status=stale age=412 max=180", "100840"},
		"heartbeat missing":   {"ossec: output: 'phage-heartbeat': status=missing reason=no-heartbeat max=180", "100840"},
		"heartbeat fresh":     {"ossec: output: 'phage-heartbeat': status=fresh age=12 max=180", "530"},
		"service inactive":    {"ossec: output: 'phage-service': inactive", "100841"},
		"service failed":      {"ossec: output: 'phage-service': failed", "100841"},
		"service activating":  {"ossec: output: 'phage-service': activating", "100841"},
		"service active":      {"ossec: output: 'phage-service': active", "530"},
		"other json":          {`{"kind":"startup","status":"armed"}`, ""},
		"other heuristic":     {`{"source_kind":"heuristic","uid":"nov-1","status":"finding","score":0.9}`, ""},
	} {
		if got := fire(t, rules, c.line); got != c.want {
			t.Errorf("%s: fired %q, want %q\n  %s", name, got, c.want, c.line)
		}
	}
	// The same records from another file trip nothing, and both location
	// forms (agent and manager-local) match.
	armedLine := line(t, startup("armed"))
	for loc, want := range map[string]string{
		"(web01) any->/var/lib/phage/audit.jsonl":           "100802",
		"/var/lib/phage/audit.jsonl":                        "100802",
		"(web01) any->/var/log/app/events.json":             "",
		"(web01) any->/var/lib/phage/audit.jsonl.1":         "",
		"(web01) any->/srv/x/var/lib/phage/audit.jsonl.bak": "",
		"/tmp/var/lib/phage/audit.jsonl":                    "",
	} {
		if got := fireAt(t, rules, armedLine, loc); got != want {
			t.Errorf("startup armed from %q fired %q, want %q", loc, got, want)
		}
	}
	unl := line(t, id.Unlearned(ev, nil, "none", time.Now()))
	if got := fireAt(t, rules, unl, "(web01) any->/var/lib/phage/audit.jsonl"); got != "" {
		t.Errorf("a novelty row read from the audit trail fired %s", got)
	}
}

func TestRuleFileIntegrity(t *testing.T) {
	rules := loadRules(t)
	ids := map[string]bool{"530": true}
	for _, r := range rules {
		n, err := strconv.Atoi(r.ID)
		if err != nil || n < 100800 || n > 100849 {
			t.Errorf("rule id %q outside Phage's range 100800-100849", r.ID)
		}
		if ids[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		ids[r.ID] = true
		if strings.TrimSpace(r.Description) == "" {
			t.Errorf("rule %s has no description", r.ID)
		}
		for _, f := range r.Fields {
			re(t, f)
		}
		if r.Regex != nil {
			re(t, *r.Regex)
		}
	}
	groups := map[string]bool{}
	for _, r := range rules {
		for _, g := range strings.Split(r.Group, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groups[g] = true
			}
		}
	}
	for _, r := range rules {
		if r.IfSid != "" && !ids[r.IfSid] {
			t.Errorf("rule %s: if_sid %s is not defined", r.ID, r.IfSid)
		}
		if r.IfMatchedGroup != "" && !groups[r.IfMatchedGroup] {
			t.Errorf("rule %s: if_matched_group %s has no rule", r.ID, r.IfMatchedGroup)
		}
		if r.Frequency > 0 && r.IfMatchedGroup == "" && r.IfSid == "" {
			t.Errorf("rule %s: a frequency rule needs what it counts", r.ID)
		}
	}
}

// The XML files must be well-formed and generic: no addresses or host names.
func TestFilesAreWellFormedAndGeneric(t *testing.T) {
	addr := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	for _, f := range []string{"phage_rules.xml", "phage_decoders.xml", "agent_ossec.conf", "phage-heartbeat-check"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f, ".xml") || strings.HasSuffix(f, ".conf") {
			// Wazuh files may hold several top-level elements: wrap them.
			d := xml.NewDecoder(strings.NewReader("<root>" + string(b) + "</root>"))
			for {
				if _, err := d.Token(); err != nil {
					if err.Error() != "EOF" {
						t.Errorf("%s is not well-formed XML: %v", f, err)
					}
					break
				}
			}
		}
		if m := addr.FindString(string(b)); m != "" {
			t.Errorf("%s names an address (%s); keep the shipped files generic", f, m)
		}
	}
}

func TestDecoderPatternCompiles(t *testing.T) {
	b, _ := os.ReadFile("phage_decoders.xml")
	var d struct {
		Regex pattern `xml:"regex"`
	}
	if err := xml.Unmarshal(b[bytes.Index(b, []byte("<decoder")):], &d); err != nil {
		t.Fatal(err)
	}
	r := re(t, d.Regex)
	m := r.FindStringSubmatch("ossec: output: 'phage-heartbeat': status=stale age=412 max=180")
	if len(m) != 3 || m[1] != "heartbeat" || m[2] != "stale" {
		t.Errorf("decoder captured %q", m)
	}
	if m := r.FindStringSubmatch("ossec: output: 'phage-service': inactive"); len(m) != 3 || m[2] != "inactive" {
		t.Errorf("decoder captured %q", m)
	}
}

// The agent-side check prints the line rule 100840 matches.
// The check sets its own PATH: a hostile PATH (a planted tac or date) is
// never used.
func TestHeartbeatCheckIgnoresCallerPATH(t *testing.T) {
	if _, err := exec.LookPath("tac"); err != nil {
		t.Skip("tac not available")
	}
	script, _ := filepath.Abs("phage-heartbeat-check")
	evil := t.TempDir()
	for _, tool := range []string{"tac", "date", "grep", "cut"} {
		os.WriteFile(filepath.Join(evil, tool), []byte("#!/bin/sh\necho PWNED\n"), 0o755)
	}
	trail := filepath.Join(t.TempDir(), "audit.jsonl")
	hb := heartbeat(audit.Health{})
	hb.Time = time.Now()
	os.WriteFile(trail, []byte(line(t, hb)+"\n"), 0o600)
	cmd := exec.Command(script, "180", trail)
	cmd.Env = []string{"PATH=" + evil}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "PWNED") || !strings.HasPrefix(string(out), "status=fresh") {
		t.Errorf("output %q: the caller's PATH was used", out)
	}
}

func TestHeartbeatCheckScript(t *testing.T) {
	for _, tool := range []string{"sh", "tac", "date", "grep", "cut"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	if out, _ := exec.Command("date", "-d", "2026-01-02T03:04:05.123456789-06:00", "+%s").Output(); len(out) == 0 {
		t.Skip("date is not GNU date")
	}
	script, _ := filepath.Abs("phage-heartbeat-check")
	dir := t.TempDir()
	trail := filepath.Join(dir, "audit.jsonl")
	write := func(entries ...audit.Entry) {
		var b bytes.Buffer
		for _, e := range entries {
			b.WriteString(line(t, e) + "\n")
		}
		os.WriteFile(trail, b.Bytes(), 0o600)
	}
	at := func(e audit.Entry, ago time.Duration) audit.Entry {
		e.Time = time.Now().Add(-ago)
		return e
	}
	run := func(args ...string) string {
		out, err := exec.Command(script, args...).Output()
		if err != nil {
			t.Fatalf("check failed: %v", err)
		}
		if bytes.Count(out, []byte("\n")) != 1 {
			t.Errorf("want exactly one line, got %q", out)
		}
		return strings.TrimSpace(string(out))
	}
	rules := loadRules(t)
	fired := func(out string) string { return fire(t, rules, "ossec: output: 'phage-heartbeat': "+out) }

	hb := heartbeat(audit.Health{})
	// A recent heartbeat, followed by newer records of other kinds.
	write(at(startup("none"), time.Hour), at(hb, 30*time.Second), at(response("notified", 0.5), time.Second))
	if out := run("180", trail); !strings.HasPrefix(out, "status=fresh") || fired(out) != "530" {
		t.Errorf("fresh: %q", out)
	}
	write(at(hb, 10*time.Minute), at(response("notified", 0.5), time.Second))
	if out := run("180", trail); !strings.HasPrefix(out, "status=stale") || fired(out) != "100840" {
		t.Errorf("stale: %q", out)
	}
	write(at(hb, -time.Hour))
	if out := run("180", trail); !strings.HasPrefix(out, "status=skew") || fired(out) != "100840" {
		t.Errorf("future heartbeat: %q", out)
	}
	// A reason mentioning a heartbeat must not count as one.
	fake := response("notified", 0.5)
	fake.Reason = `{"time":"` + time.Now().Format(time.RFC3339) + `","kind":"heartbeat"`
	write(at(startup("none"), time.Hour), fake)
	if out := run("180", trail); out != "status=missing reason=no-heartbeat max=180" || fired(out) != "100840" {
		t.Errorf("forged heartbeat text: %q", out)
	}
	if out := run("180", filepath.Join(dir, "absent")); out != "status=missing reason=no-audit-trail max=180" {
		t.Errorf("missing trail: %q", out)
	}
	if out := run("soon", trail); !strings.HasPrefix(out, "status=missing reason=bad-max-age") {
		t.Errorf("bad max: %q", out)
	}
}
