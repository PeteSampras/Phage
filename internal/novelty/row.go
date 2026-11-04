// Package novelty turns Phage verdicts into rows of homelab-next's
// `novelty_finding` table (ADR-0036 decisions 6-7), so a host's own kernel
// view reaches the lake as a second heuristic source beside the lake analyzer,
// in the same shape and the same entity namespace. Rows are advisory: nothing
// here, and nothing downstream, acts on one alone.
//
// The row shape is held by a copy of the table's JSON schema in testdata
// (see testdata/PROVENANCE). Keep the two in step.
package novelty

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
)

// Row statuses Phage writes. The lake analyzer's high_cardinality status has
// no Phage counterpart.
const (
	StatusFinding   = "finding"   // scored at or above the notify threshold
	StatusUnlearned = "unlearned" // the event's feature class has no learned baseline: no score
	StatusBurst     = "burst"     // more new rows for one profile in one bucket than the cap: no score, a signal
)

// writableTLP reports whether a row's label is one Phage may write: a
// canonical TLP 2.0 label other than red (a red row can never be written to
// the lake). Config validation refuses the rest; the sink checks again.
func writableTLP(l string) bool {
	switch l {
	case "clear", "green", "amber", "amber+strict":
		return true
	}
	return false
}

// SourceKind is the only kind a novelty row may have.
const SourceKind = "heuristic"

// Column limits from the schema (characters; Phage counts bytes, which is
// never more than characters).
const (
	maxEntity  = 512
	maxValue   = 2048
	maxMessage = 4096
	maxReason  = 512
)

// Row is one novelty_finding row. Fields Phage never fills (the lake
// analyzer's windows, columns and spec digest) are absent from the struct, so
// they are absent from the JSON, which the schema allows.
type Row struct {
	UID         string   `json:"uid"`
	Time        string   `json:"time"`
	AsOf        string   `json:"as_of"`
	Source      string   `json:"source"`
	SourceKind  string   `json:"source_kind"`
	Profile     string   `json:"profile"`
	EntityKind  string   `json:"entity_kind"`
	Entity      string   `json:"entity"`
	Value       string   `json:"value,omitempty"`
	Status      string   `json:"status"`
	Score       *float64 `json:"score,omitempty"`        // finding only
	Confidence  *float64 `json:"confidence,omitempty"`   // finding only
	Support     *float64 `json:"support,omitempty"`      // times the value was learned
	EntityTotal *float64 `json:"entity_total,omitempty"` // observations of the feature while learning
	Count       int64    `json:"count"`                  // 1 (one row per event); on a burst row, always the cap + 1
	Message     string   `json:"message"`
	Reasons     []string `json:"reasons"`
	TLP         string   `json:"tlp"`

	bucket  time.Time // start of the uid bucket (not a column)
	burstOf string    // burst rows: the status they stand for (in the uid; not a column)
}

// Identity is what names this sensor and its host in every row.
type Identity struct {
	Source     string        // output.source
	EntityKind string        // output.entity_kind
	Entity     string        // output.entity, or the host name
	TLP        string        // output.tlp
	Bucket     time.Duration // output.novelty_bucket: the uid's time bucket
}

// Profile names the row's profile: the Phage event kind, with hyphens (the
// schema's profile pattern allows no underscore): exec, connect, file-write,
// enable, creds-change, capset, self-defense, honeytoken.
func Profile(k kind.Kind) string {
	p := strings.ReplaceAll(string(k), "_", "-")
	if p == "" {
		return "unknown"
	}
	return p
}

// Value is the concrete object of the event: what an analyst looks up first.
//
//	file-write, honeytoken   the path
//	connect                  the destination ip:port ([v6]:port)
//	enable                   the operation (userns, bpf_load, io_uring, userfaultfd)
//	self-defense             the signal name or ptrace
//	exec and the rest        the executable (its comm when /proc had none)
func Value(ev model.Event) string {
	switch ev.Kind {
	case kind.FileWrite, kind.Honeytoken:
		if ev.File.Path != "" {
			return ev.File.Path
		}
	case kind.Connect:
		if ev.Net.DestIP != "" {
			return net.JoinHostPort(ev.Net.DestIP, strconv.Itoa(int(ev.Net.DestPort)))
		}
	case kind.Enable:
		if ev.EnableOp != "" {
			return ev.EnableOp
		}
	case kind.SelfDefense:
		if ev.SelfDefOp != "" {
			return ev.SelfDefOp
		}
	}
	if ev.Exe != "" {
		return ev.Exe
	}
	return ev.Comm
}

// Finding builds the row for a verdict at or above the notify threshold.
// baselineSHA names the baseline that scored it (a reason, since the schema's
// spec_digest means the lake analyzer's spec).
func (id Identity) Finding(ev model.Event, v verdict.Verdict, baselineSHA string, asOf time.Time) Row {
	reasons := sortedReasons(v)
	r := id.base(ev, StatusFinding, asOf)
	score := round(v.Score)
	r.Score = &score
	conf := 1.0
	if len(reasons) > 0 {
		top := reasons[0]
		conf = top.Confidence
		if top.Samples > 0 {
			sup, tot := float64(top.Support), float64(top.Samples)
			r.Support, r.EntityTotal = &sup, &tot
		}
	}
	if conf <= 0 || conf > 1 { // an intrinsic reason that did not say
		conf = 1
	}
	conf = round(conf)
	r.Confidence = &conf

	lines := make([]string, 0, len(reasons)+1)
	for _, re := range reasons {
		line := fmt.Sprintf("%s: %s (contribution %.2f", re.Feature, re.Detail, re.Contribution)
		if re.Samples > 0 {
			line += fmt.Sprintf("; surprise %.2f, confidence %.2f, seen %d of %d", re.Surprise, re.Confidence, re.Support, re.Samples)
		}
		lines = append(lines, line+")")
	}
	lines = append(lines, "baseline sha256:"+baselineSHA)
	r.Reasons = clipAll(lines, maxReason)
	what := "(no anomalous features)"
	if len(reasons) > 0 {
		what = reasons[0].Detail
	}
	r.Message = clip(fmt.Sprintf("%s: %s %s by %s (pid %d): %s; score %.2f, confidence %.2f",
		r.Entity, r.Profile, r.Value, ev.Comm, ev.PID, what, score, conf), maxMessage)
	return r
}

// Unlearned builds the row for an event whose feature class (every feature
// key its extractor produced) has no observations in the baseline. Phage's
// scorer treats such a feature as neutral, which used to mean silence: a host
// that never egressed while learning never alerted on its first egress. The
// row reports it instead, unscored, as the lake analyzer reports an entity
// with no learned support.
func (id Identity) Unlearned(ev model.Event, keys []string, baselineSHA string, asOf time.Time) Row {
	r := id.base(ev, StatusUnlearned, asOf)
	zero := 0.0
	r.Support, r.EntityTotal = &zero, &zero
	sorted := append([]string(nil), keys...)
	sort.Strings(sorted)
	r.Reasons = clipAll([]string{
		"no observations in the baseline for " + strings.Join(sorted, ", "),
		"baseline sha256:" + baselineSHA,
	}, maxReason)
	r.Message = clip(fmt.Sprintf("%s: %s %s by %s (pid %d): this kind of event was never seen while learning, so it is not scored (unlearned)",
		r.Entity, r.Profile, r.Value, ev.Comm, ev.PID), maxMessage)
	return r
}

func (id Identity) base(ev model.Event, status string, asOf time.Time) Row {
	t := ev.Time
	if t.IsZero() {
		t = asOf
	}
	r := Row{
		Time:       Timestamp(t),
		AsOf:       Timestamp(asOf),
		Source:     id.Source,
		SourceKind: SourceKind,
		Profile:    Profile(ev.Kind),
		EntityKind: id.EntityKind,
		Entity:     clip(id.Entity, maxEntity),
		Value:      clip(Value(ev), maxValue),
		Status:     status,
		Count:      1,
		TLP:        id.TLP,
	}
	r.bucket = id.bucketOf(t)
	r.UID = id.uid(r)
	return r
}

// Burst builds the row that stands for every new row of trigger's status
// (finding or unlearned) and profile past the per-bucket cap: no value, no
// score. Its count is always the cap + 1 (the rows seen when the cap was
// passed); the true total is not known when it is written, and the rest are
// counted in the heartbeat's novelty_over_cap. Its time is the triggering
// event's; its uid is one per status, profile, entity and bucket.
func (id Identity) Burst(trigger Row, count int, asOf time.Time) Row {
	r := trigger
	r.burstOf = trigger.Status
	r.Value, r.Status = "", StatusBurst
	r.Score, r.Confidence, r.Support, r.EntityTotal = nil, nil, nil, nil
	r.Count = int64(count)
	r.AsOf = Timestamp(asOf)
	r.UID = id.uid(r)
	r.Reasons = clipAll([]string{
		fmt.Sprintf("more than novelty_max_per_bucket %d new %s %s rows in the bucket starting %s: count is always the cap + 1; the rest are counted in the heartbeat (novelty_over_cap), not written",
			count-1, r.burstOf, r.Profile, Timestamp(r.bucket)),
	}, maxReason)
	r.Message = clip(fmt.Sprintf("%s: more than %d new %s %s rows in one bucket (a burst, such as a scan or a flood); the total is in the heartbeat's novelty_over_cap (burst)",
		r.Entity, count-1, r.burstOf, r.Profile), maxMessage)
	return r
}

// uid is a digest of the source, profile, status, entity kind, entity, value
// and the start of the event's time bucket: the same finding within one
// bucket has one uid, so the lake's (source, uid) key keeps it once however
// often the event repeats, and a later bucket is a new row.
func (id Identity) uid(r Row) string {
	h := sha256.New()
	for _, f := range []string{r.Source, r.Profile, r.Status + r.burstOf, r.EntityKind, r.Entity, r.Value,
		strconv.FormatInt(r.bucket.Unix(), 10)} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return "phage-" + hex.EncodeToString(h.Sum(nil))[:40]
}

func (id Identity) bucketOf(t time.Time) time.Time {
	b := id.Bucket
	if b <= 0 {
		b = time.Hour
	}
	return t.UTC().Truncate(b)
}

// Timestamp formats a time as the lake stores it: RFC 3339, UTC, with
// microseconds.
func Timestamp(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000Z07:00")
}

// sortedReasons orders a verdict's reasons by contribution, then by feature,
// so the top reason and the reasons list are deterministic (the scorer ranges
// over a map).
func sortedReasons(v verdict.Verdict) []verdict.Reason {
	out := append([]verdict.Reason(nil), v.Reasons...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Contribution != out[j].Contribution {
			return out[i].Contribution > out[j].Contribution
		}
		return out[i].Feature < out[j].Feature
	})
	return out
}

func round(f float64) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(f, 'f', 4, 64), 64)
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// clip truncates s to at most n bytes on a rune boundary, marking the cut.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	const mark = "..."
	cut := n - len(mark)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + mark
}

func clipAll(l []string, n int) []string {
	for i := range l {
		l[i] = clip(l[i], n)
	}
	return l
}
