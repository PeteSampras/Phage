// Package app wires the pipeline together and owns the daemon's run loop. It is
// the one place that knows about every stage; each stage still knows only its
// neighbours. Keeping the wiring here lets cmd/phaged stay a thin entrypoint.
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AzozzALFiras/Phage/internal/agent/config"
	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/analysis/feature"
	"github.com/AzozzALFiras/Phage/internal/analysis/scorer"
	"github.com/AzozzALFiras/Phage/internal/analysis/scorer/behavioral"
	"github.com/AzozzALFiras/Phage/internal/analysis/verdict"
	"github.com/AzozzALFiras/Phage/internal/audit"
	"github.com/AzozzALFiras/Phage/internal/control"
	"github.com/AzozzALFiras/Phage/internal/enrich"
	"github.com/AzozzALFiras/Phage/internal/event/kind"
	"github.com/AzozzALFiras/Phage/internal/event/model"
	"github.com/AzozzALFiras/Phage/internal/honeytoken"
	"github.com/AzozzALFiras/Phage/internal/logsafe"
	"github.com/AzozzALFiras/Phage/internal/policy/mode"
	"github.com/AzozzALFiras/Phage/internal/policy/response"
	"github.com/AzozzALFiras/Phage/internal/response/action"
	"github.com/AzozzALFiras/Phage/internal/response/contain"
	"github.com/AzozzALFiras/Phage/internal/response/netquarantine"
	"github.com/AzozzALFiras/Phage/internal/selfheal"
	"github.com/AzozzALFiras/Phage/internal/selfprotect"
	"github.com/AzozzALFiras/Phage/internal/sensor/decode"
	"github.com/AzozzALFiras/Phage/internal/sensor/loader"
	"github.com/AzozzALFiras/Phage/internal/store/profile"
)

// App is a configured, runnable daemon.
type App struct {
	cfg           config.Config
	objPath       string
	store         profile.Repository
	profile       *baseline.Profile
	enricher      enrich.Enricher
	extract       feature.Privilege
	execExtract   feature.Exec
	netExtract    feature.Network
	fileExtract   feature.Filesystem
	enableExtract feature.Enable
	scorer        scorer.Scorer
	freezer       freezer
	netq          isolator // nil unless isolate armed and loaded
	healer        *selfheal.Store
	audit         *audit.Writer

	meta Meta

	// Identity used to trust events — never the attacker-chosen comm. selfPID is
	// the agent's own tgid; getppid returns its current parent (consulted only
	// when dev.trust_launcher_signals is on). exeOf resolves /proc/<pid>/exe
	// (swappable in tests).
	selfPID int32
	getppid func() int
	proc    procView // /proc reads (fake in tests)

	healGate  func(v procView, pid int32, path string) (bool, string) // writer-view check before a heal
	healDelay func()                                                  // pause before a heal (the write lands)
	healWG    sync.WaitGroup                                          // running heals (tests wait on it)
	sshd      *sshdIdentity                                           // host sshd binaries by inode

	started time.Time
	// counters and the recent-alerts ring back the control interface.
	mu          sync.Mutex
	nEvents     uint64
	nAlerts     uint64
	nContained  uint64
	recent      []control.Alert
	recentLimit int

	// graduated-response state: which processes are contained, at what rung, and
	// when they last drew a high verdict (for escalation and auto-release).
	contMu    sync.Mutex
	contained map[int32]*contState
}

// freezer and isolator are the two containment actuators (cgroup freezer and
// eBPF network quarantine), behind interfaces so the response path can be
// tested without a kernel.
type freezer interface {
	Freeze(pid int32) error
	Thaw(pid int32) error
}

type isolator interface {
	Isolate(pid int32) error
	Release(pid int32) error
}

type contState struct {
	rung action.Type
	last time.Time
	comm string
}

// Meta is what the entrypoint knows about this run beyond the config: the
// build version and any features a -mode downgrade switched off.
type Meta struct {
	Version        string
	Disarmed       []string  // host-modifying features switched off by a -mode downgrade
	DowngradedFrom mode.Mode // the config file's mode, when Disarmed is non-empty
}

// New builds an App from config, the path to the compiled eBPF object, the
// repository used to persist the learned baseline, and run metadata.
func New(cfg config.Config, objPath string, store profile.Repository, meta Meta) *App {
	p := baseline.NewProfile()
	return &App{
		cfg:         cfg,
		objPath:     objPath,
		store:       store,
		profile:     p,
		extract:     feature.Privilege{},
		scorer:      behavioral.New(p), // bound to p; sees whatever we load into it
		freezer:     contain.NewFreezer(),
		started:     time.Now(),
		recentLimit: 100,
		contained:   map[int32]*contState{},
		meta:        meta,
		selfPID:     int32(os.Getpid()),
		getppid:     os.Getppid,
		proc:        hostProc{},
		healGate:    writerSeesHostFile,
		healDelay:   func() { time.Sleep(250 * time.Millisecond) },
		sshd:        newSSHDIdentity(),
	}
}

// Run loads the baseline and the sensor, then processes events until ctx is
// cancelled. In learn mode it updates and persists the baseline; in alert/
// enforce mode it scores each event against the baseline and acts via the
// graduated-response matrix.
func (a *App) Run(ctx context.Context) error {
	if err := a.store.Load(a.profile); err != nil {
		return err
	}

	aw, err := audit.Open(a.cfg.AuditPath)
	if err != nil {
		return err
	}
	a.audit = aw
	defer a.audit.Close()

	sensor, err := loader.Load(a.objPath)
	if err != nil {
		return err
	}
	defer sensor.Close()

	// Cancelling the context closes the sensor, which unblocks Read below.
	go func() {
		<-ctx.Done()
		sensor.Close()
	}()

	// Arm self-defense: tell the kernel sensors our own pid so they flag any
	// signal/ptrace aimed at the agent (anti-blinding).
	if err := sensor.SetSelfPID(uint32(os.Getpid())); err != nil {
		log.Printf("self-defense arm: %v", err)
	}
	go a.deadMansSwitch(ctx)
	go a.releaseLoop(ctx)

	armed, failed, disarm := a.armFeatures(a.realArmers(sensor))
	defer disarm()

	if err := a.announceStartup(armed, failed); err != nil {
		return err // fatal: an armed host we cannot account for must not run
	}

	log.Printf("sensors attached (creds, exec, egress, files, kernel-enabling ops, self-defense); mode=%s obj=%s", a.cfg.Mode, a.objPath)

	if srv, err := control.Serve(ctx, a.cfg.ControlPath, a); err != nil {
		log.Printf("control socket disabled: %v", err)
	} else if srv != nil {
		defer srv.Close()
		log.Printf("control socket: %s", a.cfg.ControlPath)
	}

	for {
		raw, err := sensor.Read()
		if err != nil {
			if ctx.Err() != nil {
				return a.onShutdown() // clean shutdown
			}
			return err
		}

		ev, err := decode.Event(raw)
		if err != nil {
			log.Printf("decode: %v", err)
			continue
		}
		ev = a.enricher.Enrich(ev)

		// Self-defense is not a learned/averaged signal: an attempt to kill,
		// stop, or ptrace the agent by anything other than its supervisor is
		// intrinsically critical and is surfaced in every mode (including learn).
		if ev.Kind == kind.SelfDefense {
			a.mu.Lock()
			a.nEvents++
			a.mu.Unlock()
			a.respondSelfDefense(ev)
			continue
		}

		// A read of a planted decoy is intrinsically high-confidence (nothing
		// legitimate references it) — surfaced directly, not via the baseline.
		if ev.Kind == kind.Honeytoken {
			a.mu.Lock()
			a.nEvents++
			a.mu.Unlock()
			a.respondHoneytoken(ev)
			continue
		}

		// The agent's own file writes (e.g. a self-heal restore) are never a
		// threat — don't score them, and never let them re-trigger a heal. The
		// agent is recognised by its tgid: any process can name itself "phaged".
		if ev.Kind == kind.FileWrite && a.isSelf(ev.PID) {
			a.mu.Lock()
			a.nEvents++
			a.mu.Unlock()
			continue
		}

		var vec feature.Vector
		switch ev.Kind {
		case kind.Exec:
			vec = a.execExtract.Extract(ev)
		case kind.Connect:
			vec = a.netExtract.Extract(ev)
		case kind.FileWrite:
			vec = a.fileExtract.Extract(ev)
		case kind.Enable:
			vec = a.enableExtract.Extract(ev)
		default:
			vec = a.extract.Extract(ev)
		}

		a.mu.Lock()
		a.nEvents++
		a.mu.Unlock()

		if a.cfg.Mode == mode.Learn {
			for k, v := range vec {
				a.profile.Observe(k, v)
			}
			continue
		}

		// alert / enforce: score against the learned baseline, then let the
		// graduated-response matrix pick the least-invasive sufficient action.
		v := a.scorer.Score(vec)
		want := response.Decide(ev.Kind, v.Score, a.cfg.Mode,
			response.Thresholds(a.cfg.Thresholds),
			response.Context{Interactive: ev.Session.Interactive, RaisedToRoot: ev.RaisedToRoot()})
		if want != action.None {
			a.respond(ev, v, want)
		}
	}
}

// onShutdown persists the baseline when we have been learning.
func (a *App) onShutdown() error {
	if a.cfg.Mode != mode.Learn {
		return nil
	}
	if err := a.store.Save(a.profile); err != nil {
		log.Printf("save baseline: %v", err)
		return err
	}
	log.Printf("baseline saved")
	return nil
}

// respond logs the verdict, records it to the audit trail, and carries out the
// action the matrix chose. Containment (isolate/freeze) is reached only in
// enforce mode and only above the contain threshold; alert mode yields Notify.
func (a *App) respond(ev model.Event, v verdict.Verdict, want action.Type) {
	requested := want // what the response matrix judged the verdict to justify
	reason := describe(ev, v)

	// Escalation / de-dup: if this process is already contained at an equal or
	// stronger rung, refresh its lease and don't re-actuate or spam the log —
	// but still heal a malicious write and record the verdict: the process
	// being contained says nothing about the file it just wrote.
	a.contMu.Lock()
	if st := a.contained[ev.PID]; st != nil && response.Rung(want) <= response.Rung(st.rung) {
		st.last = time.Now()
		rung := st.rung
		a.contMu.Unlock()
		reason = a.maybeHeal(ev, v, reason)
		a.recordResponse(ev, v, requested, rung, "already_contained", reason)
		return
	}
	a.contMu.Unlock()

	parent := ev.ParentComm
	if parent == "" && len(ev.Lineage) > 0 {
		parent = ev.Lineage[0].Comm
	}

	applied, outcome := a.actuate(ev, requested)
	contained := outcome == outcomeContained
	reason = a.maybeHeal(ev, v, reason)

	// Logged and audited AFTER actuation, so the trail says what was asked
	// for, what was done, and how it went. Every attacker-influenced string is
	// escaped exactly once here (comm/parent with %q, the free-text reason and
	// outcome with logsafe.Clean), so a crafted name holding a newline or control bytes
	// cannot forge an extra journal line.
	log.Printf("%s score=%.2f requested=%s action=%s outcome=\"%s\" pid=%d comm=%q parent=%q uid=%d->euid=%d interactive=%t :: reason=\"%s\"",
		strings.ToUpper(labelFor(v.Score)), v.Score, requested, applied, logsafe.Clean(outcome),
		ev.PID, ev.Comm, parent, ev.Creds.UID, ev.Creds.EUID, ev.Session.Interactive, logsafe.Clean(reason))
	if contained {
		a.contMu.Lock()
		a.contained[ev.PID] = &contState{rung: applied, last: time.Now(), comm: ev.Comm}
		a.contMu.Unlock()
		a.mu.Lock()
		a.nContained++
		a.mu.Unlock()
	}
	a.recordResponse(ev, v, requested, applied, outcome, reason)
}

// describe builds the human reason for a verdict, raw (escaped at output).
func describe(ev model.Event, v verdict.Verdict) string {
	reason := reasons(v)
	// For egress anomalies, the concrete destination is the operator's first
	// question; keep it in the reason and the audit trail even though the IP is
	// deliberately not a learned feature.
	if ev.Kind == kind.Connect && ev.Net.DestIP != "" {
		reason = fmt.Sprintf("%s (-> %s:%d)", reason, ev.Net.DestIP, ev.Net.DestPort)
	}
	// For persistence anomalies, the concrete file written is the operator's
	// first question; keep it in the reason and the audit trail even though the
	// learned feature is the coarse class, not the path.
	if ev.Kind == kind.FileWrite && ev.File.Path != "" {
		reason = fmt.Sprintf("%s (wrote %s)", reason, ev.File.Path)
	}
	if ev.Kind == kind.Enable && ev.EnableOp != "" {
		reason = fmt.Sprintf("%s (op: %s)", reason, ev.EnableOp)
	}
	return reason
}

// recordResponse writes the response audit record and the control-socket
// alert (they always carry the same fields) and counts the alert.
func (a *App) recordResponse(ev model.Event, v verdict.Verdict, requested, applied action.Type, outcome, reason string) {
	if err := a.audit.Record(audit.Entry{
		Kind: audit.KindResponse, Requested: string(requested), Action: string(applied), Outcome: outcome,
		Score: v.Score, PID: ev.PID, Comm: ev.Comm, Reason: reason,
	}); err != nil && err != audit.ErrDisabled {
		log.Printf("audit: %v", err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nAlerts++
	a.recent = append(a.recent, control.Alert{
		Time: time.Now().UTC().Format(time.RFC3339), Score: v.Score,
		Requested: string(requested), Action: string(applied), Outcome: outcome,
		PID: ev.PID, Comm: ev.Comm, Reason: reason,
	})
	if len(a.recent) > a.recentLimit {
		a.recent = a.recent[len(a.recent)-a.recentLimit:]
	}
}

// maybeHeal schedules a self-heal for a malicious write to a snapshotted
// sentinel and returns the reason, annotated if the heal was skipped. Gated on
// the score crossing the containment threshold (the write is judged
// malicious), independent of any process containment.
func (a *App) maybeHeal(ev model.Event, v verdict.Verdict, reason string) string {
	if ev.Kind != kind.FileWrite || v.Score < a.cfg.Thresholds.Contain ||
		!a.cfg.Armed(config.FeatureSelfHeal) || a.healer == nil || !a.healer.Watched(ev.File.Path) {
		return reason
	}
	// The event's path was resolved in the WRITER's view of the filesystem.
	// Heal only if that names the host's sentinel inode (or, writer gone, let
	// the host file's own content decide).
	if ok, why := a.healGate(a.proc, ev.PID, ev.File.Path); !ok {
		log.Printf("SELF-HEAL %q SKIPPED (%s) — alert only", ev.File.Path, why)
		return fmt.Sprintf("%s [self-heal skipped: %s]", reason, why)
	}
	// One owner per path; writes during a running heal set its dirty bit, so
	// it heals again afterwards instead of missing them.
	if a.healer.Claim(ev.File.Path) {
		a.healWG.Add(1)
		go a.selfHeal(ev.File.Path, ev.PID, ev.Comm)
	}
	return reason
}

const (
	outcomeContained = "contained"
	outcomeNotified  = "notified"
)

// actuate carries out the matrix's choice as far as the config and the safety
// gate allow, and reports the rung actually applied and how it went:
// contained | notified | skipped:<why> | failed:<err>.
func (a *App) actuate(ev model.Event, requested action.Type) (action.Type, string) {
	want, gateNote := a.gate(requested)
	if gateNote != "" {
		return action.Notify, "skipped:" + gateNote
	}
	switch want {
	case action.None:
		return action.None, "none"
	case action.Notify:
		return action.Notify, outcomeNotified
	}
	if ok, why := containmentSafe(ev, a.selfPID, a.proc, a.sshd); !ok {
		log.Printf("CONTAIN pid=%d comm=%q %s SKIPPED (%s) — alert only", ev.PID, ev.Comm, strings.ToUpper(string(want)), why)
		return action.Notify, "skipped:" + why
	}
	if want == action.Isolate {
		if a.netq != nil {
			if err := a.netq.Isolate(ev.PID); err != nil {
				log.Printf("ISOLATE pid=%d failed: %v", ev.PID, err)
				return action.Notify, fmt.Sprintf("failed:isolate: %v", err)
			}
			log.Printf("CONTAIN pid=%d comm=%q ISOLATED (egress severed, process alive, reversible)", ev.PID, ev.Comm)
			return action.Isolate, outcomeContained
		}
		if !a.cfg.Armed(config.FeatureFreeze) {
			log.Printf("ISOLATE pid=%d unavailable (network quarantine not loaded) and freeze not armed — alert only", ev.PID)
			return action.Notify, "skipped:network quarantine not loaded and freeze not armed"
		}
		want = action.Freeze // isolation armed but failed to load — fall back to freeze
	}
	if want == action.Freeze {
		if err := a.freezer.Freeze(ev.PID); err != nil {
			log.Printf("CONTAIN pid=%d failed: %v", ev.PID, err)
			return action.Notify, fmt.Sprintf("failed:freeze: %v", err)
		}
		log.Printf("CONTAIN pid=%d comm=%q FROZEN (process tree quarantined, reversible)", ev.PID, ev.Comm)
		return action.Freeze, outcomeContained
	}
	return action.Notify, fmt.Sprintf("skipped:%s not armable", want)
}

// armers are the loaders for each host-modifying feature. Each returns a
// cleanup (or the armed object) and an error. They are injected so a test can
// prove that armFeatures calls exactly the loaders config.Armed allows.
type armers struct {
	honeytokens func() (cleanup func(), detail string, err error)
	selfProtect func() (cleanup func(), err error)
	isolate     func() (isolator, func(), error)
	selfHeal    func() (*selfheal.Store, error)
}

// armFeatures arms every host-modifying feature config.Armed allows — and
// nothing else — returning what armed, what was requested but failed, and one
// cleanup that disarms everything in reverse order.
func (a *App) armFeatures(ar armers) (armed, failed []string, disarm func()) {
	var cleanups []func()
	disarm = func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	note := func(feature string, err error) bool {
		if err != nil {
			log.Printf("%s: %v; running without it", feature, err)
			failed = append(failed, feature)
			return false
		}
		armed = append(armed, feature)
		return true
	}

	// Honeytokens (deception.honeytokens; alert or enforce).
	if a.cfg.Armed(config.FeatureHoneytokens) {
		c, detail, err := ar.honeytokens()
		if note(config.FeatureHoneytokens, err) {
			cleanups = append(cleanups, c)
			log.Printf("honeytokens planted: %s — any read of one is a high-confidence alert", detail)
		}
	}
	// Tamper-resistance (enforcement.self_protect).
	if a.cfg.Armed(config.FeatureSelfProtect) {
		c, err := ar.selfProtect()
		if note(config.FeatureSelfProtect, err) {
			cleanups = append(cleanups, c)
			log.Printf("self-protection ARMED: signals that would kill the agent are denied (except from pid 1); systemctl stop and reboot still work")
		}
	}
	// Network quarantine (enforcement.isolate). If it cannot load, egress
	// verdicts fall back to freeze only when freeze is armed too.
	if a.cfg.Armed(config.FeatureIsolate) {
		nq, c, err := ar.isolate()
		if note(config.FeatureIsolate, err) {
			a.netq = nq
			cleanups = append(cleanups, c)
		}
	}
	// Freeze (enforcement.freeze) has nothing to load: the cgroup freezer is
	// driven on demand.
	if a.cfg.Armed(config.FeatureFreeze) {
		armed = append(armed, config.FeatureFreeze)
	}
	// Self-heal (enforcement.self_heal): snapshot the sentinels now.
	if a.cfg.Armed(config.FeatureSelfHeal) {
		h, err := ar.selfHeal()
		if note(config.FeatureSelfHeal, err) {
			a.healer = h
		}
	}
	return armed, failed, disarm
}

// realArmers are the production loaders.
func (a *App) realArmers(sensor *loader.Sensor) armers {
	objDir := filepath.Dir(a.objPath)
	return armers{
		honeytokens: func() (func(), string, error) {
			// Decoys a previous run left behind (e.g. after a crash) are
			// re-adopted from the record next to the baseline.
			ht := honeytoken.New(filepath.Join(filepath.Dir(a.cfg.StatePath), "honeytokens.json"), honeytoken.Decoys)
			planted, err := ht.Seed()
			if err != nil {
				return nil, "", err
			}
			if len(planted) == 0 {
				return nil, "", errors.New("none planted (real files at every decoy path)")
			}
			if err := sensor.SetHoneytokens(honeytoken.Inodes(planted)); err != nil {
				ht.Shutdown(planted)
				return nil, "", err
			}
			adopted := 0
			for _, p := range planted {
				if p.Adopted {
					adopted++
				}
			}
			return func() { ht.Shutdown(planted) },
				fmt.Sprintf("%d decoys (%d re-adopted from a previous run)", len(planted), adopted), nil
		},
		selfProtect: func() (func(), error) {
			if !selfprotect.Available() {
				return nil, errors.New("BPF LSM is not active")
			}
			// The LSM always allows pid 1 and the agent itself; the launcher
			// slot gets a real pid only when dev.trust_launcher_signals says so
			// (pid 1 otherwise, which adds nothing).
			launcher := uint32(1)
			if a.cfg.Dev.TrustLauncherSignals {
				launcher = uint32(os.Getppid())
			}
			g, err := selfprotect.Arm(filepath.Join(objDir, "selfprotect.bpf.o"), uint32(os.Getpid()), launcher)
			if err != nil {
				return nil, err
			}
			return func() { g.Close() }, nil
		},
		isolate: func() (isolator, func(), error) {
			nq, err := netquarantine.New(filepath.Join(objDir, "netquarantine.bpf.o"))
			if err != nil {
				return nil, nil, fmt.Errorf("network quarantine unavailable: %w (egress verdicts will freeze if freeze is armed, else alert)", err)
			}
			return nq, func() { nq.Close() }, nil
		},
		selfHeal: func() (*selfheal.Store, error) {
			h, err := selfheal.New("/var/lib/phage/quarantine")
			if err != nil {
				return nil, err
			}
			n := h.SnapshotAll(selfheal.DefaultSentinels())
			log.Printf("self-heal armed: %d sentinel file(s) snapshotted (restored on malicious write)", n)
			return h, nil
		},
	}
}

// announceStartup makes every start accountable. It logs one structured
// startup line and writes a `startup` audit record on every start (mode, what
// armed, config path + sha256, version); when anything host-modifying armed it
// also logs the ENFORCEMENT ARMED line and writes an `enforcement_armed`
// record, and when a -mode downgrade switched features off it logs that and
// writes a `disarmed` record. Failing to write any of these is fatal.
func (a *App) announceStartup(armed, failed []string) error {
	status := audit.StatusNone
	switch {
	case len(armed) > 0:
		status = audit.StatusArmed
	case len(failed) > 0:
		status = audit.StatusFailed
	}
	src := a.cfg.Source
	base := audit.Entry{
		PID: a.selfPID, Comm: "phaged", Mode: a.cfg.Mode.String(), Version: a.meta.Version,
		ConfigPath: src.Path, ConfigSHA256: src.SHA256,
	}
	prov := fmt.Sprintf("config_path=%q config_sha256=%s version=%q pid=%d",
		src.Path, orNone(src.SHA256), a.meta.Version, a.selfPID)

	var records []audit.Entry
	if len(a.meta.Disarmed) > 0 {
		log.Printf("ENFORCEMENT DISARMED event=disarmed from_mode=%s mode=%s disarmed=%s %s — -mode downgrade overrides the config file for this run",
			a.meta.DowngradedFrom, a.cfg.Mode, joinOrNone(a.meta.Disarmed), prov)
		e := base
		e.Kind, e.Action, e.Disarmed = audit.KindDisarmed, audit.KindDisarmed, a.meta.Disarmed
		e.Reason = fmt.Sprintf("-mode %s over a %s config switched off: %s", a.cfg.Mode, a.meta.DowngradedFrom, joinOrNone(a.meta.Disarmed))
		records = append(records, e)
	}
	if status == audit.StatusArmed {
		log.Printf("ENFORCEMENT ARMED event=enforcement_armed status=%s mode=%s features=%s failed=%s %s",
			status, a.cfg.Mode, joinOrNone(armed), joinOrNone(failed), prov)
		e := base
		e.Kind, e.Action, e.Status, e.Features, e.Failed = audit.KindEnforcementArmed, audit.KindEnforcementArmed, status, armed, failed
		e.Reason = fmt.Sprintf("host-modifying features armed: %s; requested but not armed: %s", joinOrNone(armed), joinOrNone(failed))
		records = append(records, e)
	}
	log.Printf("startup event=startup status=%s mode=%s features=%s failed=%s %s",
		status, a.cfg.Mode, joinOrNone(armed), joinOrNone(failed), prov)
	e := base
	e.Kind, e.Action, e.Status, e.Features, e.Failed, e.Disarmed = audit.KindStartup, audit.KindStartup, status, armed, failed, a.meta.Disarmed
	e.Reason = fmt.Sprintf("phaged started: mode=%s status=%s", a.cfg.Mode, status)
	records = append(records, e)

	if a.audit == nil {
		log.Printf("audit trail disabled (audit_path empty): startup not recorded")
		return nil
	}
	for _, r := range records {
		if err := a.audit.Record(r); err != nil {
			return fmt.Errorf("write %s audit record: %w", r.Kind, err)
		}
	}
	if err := a.audit.Sync(); err != nil {
		return fmt.Errorf("sync audit trail: %w", err)
	}
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ",")
}

// gate maps the action the response matrix chose onto what the operator's
// config allows: a containment rung whose enforcement key is off (or any rung
// outside enforce mode) becomes Notify, with a short note for the log/audit.
func (a *App) gate(want action.Type) (action.Type, string) {
	switch want {
	case action.None, action.Notify:
		return want, ""
	case action.Isolate:
		if a.cfg.Armed(config.FeatureIsolate) {
			return want, ""
		}
		return action.Notify, "isolate not armed: alert only"
	case action.Freeze:
		if a.cfg.Armed(config.FeatureFreeze) {
			return want, ""
		}
		return action.Notify, "freeze not armed: alert only"
	default: // Kill (never chosen today) or anything new: no config key allows it
		return action.Notify, fmt.Sprintf("%s not armable: alert only", want)
	}
}

// Status implements control.Handler.
func (a *App) Status() control.Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	return control.Status{
		Mode:      a.cfg.Mode.String(),
		Uptime:    time.Since(a.started).Truncate(time.Second).String(),
		Events:    a.nEvents,
		Alerts:    a.nAlerts,
		Contained: a.nContained,
	}
}

// RecentAlerts implements control.Handler: the last n surfaced verdicts.
func (a *App) RecentAlerts(n int) []control.Alert {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n > len(a.recent) {
		n = len(a.recent)
	}
	out := make([]control.Alert, n)
	copy(out, a.recent[len(a.recent)-n:])
	return out
}

// Thaw implements control.Handler: release a quarantined process (false
// positive) — both a cgroup-freeze and a network isolation, whichever applies.
func (a *App) Thaw(pid int32) error {
	if a.netq != nil {
		_ = a.netq.Release(pid)
	}
	a.contMu.Lock()
	delete(a.contained, pid)
	a.contMu.Unlock()
	return a.freezer.Thaw(pid)
}

// isSelf reports whether pid (a tgid, as the sensors report it) is the agent.
func (a *App) isSelf(pid int32) bool { return pid == a.selfPID }

// isSupervisor reports whether pid may legitimately send the agent a stop
// signal: pid 1 (systemd/init, which is what `systemctl stop` and shutdown
// signal from). A lethal signal from anything else is a tamper attempt —
// whatever it calls itself; upstream trusted the comm names "systemd"/"init",
// which any process can adopt. For hand runs, dev.trust_launcher_signals also
// trusts the agent's CURRENT parent, re-read at decision time so a launcher
// that has exited (and whose pid may be reused) is never trusted.
func (a *App) isSupervisor(pid int32) bool {
	if pid == 1 {
		return true
	}
	if !a.cfg.Dev.TrustLauncherSignals || a.getppid == nil {
		return false
	}
	ppid := int32(a.getppid())
	return ppid > 1 && pid == ppid
}

// respondSelfDefense handles an attack on the agent itself. It is deliberately
// outside the learned scorer: tampering with the monitor is self-evidently
// hostile and must surface even on a thin/empty baseline. The only benign case
// is the service supervisor sending a stop signal during shutdown.
func (a *App) respondSelfDefense(ev model.Event) {
	if ev.SelfDefOp != "ptrace" && a.isSupervisor(ev.PID) {
		return // legitimate service stop by the supervisor
	}
	detail := fmt.Sprintf("attempt to tamper with the Phage agent: %s by %s (pid %d) — monitor blinding/kill attempt",
		ev.SelfDefOp, ev.Comm, ev.PID)
	v := verdict.Verdict{
		Score:   1.0,
		Reasons: []verdict.Reason{{Feature: "self.tamper", Contribution: 1.0, Detail: detail}},
	}
	want := response.Decide(kind.SelfDefense, 1.0, a.cfg.Mode, response.Thresholds(a.cfg.Thresholds),
		response.Context{Interactive: ev.Session.Interactive, RaisedToRoot: ev.RaisedToRoot()})
	a.respond(ev, v, want)
}

// respondHoneytoken handles a read of a planted decoy. Nothing legitimate reads
// these files, so it is a near-zero-false-positive, top-severity verdict surfaced
// in every mode; the agent itself is excluded (it plants them).
func (a *App) respondHoneytoken(ev model.Event) {
	if a.isSelf(ev.PID) {
		return
	}
	detail := fmt.Sprintf("read a planted honeytoken decoy %s — near-certain credential theft / intruder snooping", ev.File.Path)
	v := verdict.Verdict{
		Score:   1.0,
		Reasons: []verdict.Reason{{Feature: "honeytoken", Contribution: 1.0, Detail: detail}},
	}
	want := response.Decide(kind.Honeytoken, 1.0, a.cfg.Mode, response.Thresholds(a.cfg.Thresholds),
		response.Context{Interactive: ev.Session.Interactive, RaisedToRoot: ev.RaisedToRoot()})
	a.respond(ev, v, want)
}

// releaseLoop is graduated de-escalation: a contained process that draws no new
// high verdict for a quiet window is automatically released. Containment is a
// lease, not a life sentence — the reversible counterpart to escalation, and
// part of why enforce is safe to leave on.
//
// Crucially this applies only to the Isolate rung. An isolated process keeps
// running and can still act and emit events, so a genuinely quiet window is real
// evidence it was benign or transient, and restoring its egress is the right,
// reversible call. A frozen process is the opposite: it is silent *by
// construction*, so "no further evidence" is an artifact of the freeze, not a
// sign of innocence — and freeze is reserved for near-certain verdicts (a
// honeytoken read, a confirmed no-session privilege escalation). Those are held
// for a human to thaw (`phage thaw`), never auto-released on a timer. Dead pids
// are reaped so the lease table does not grow without bound.
func (a *App) releaseLoop(ctx context.Context) {
	after := time.Duration(a.cfg.ReleaseAfter) * time.Second
	if after <= 0 {
		after = 300 * time.Second
	}
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			a.contMu.Lock()
			for pid, st := range a.contained {
				if !pidAlive(pid) { // process gone (exited, or admin killed it): reap the lease
					delete(a.contained, pid)
					continue
				}
				if now.Sub(st.last) < after {
					continue
				}
				if st.rung != action.Isolate {
					continue // freeze is a hold-for-review, not a lease — only a human releases it
				}
				if a.netq != nil {
					_ = a.netq.Release(pid)
				}
				log.Printf("DE-ESCALATED pid=%d comm=%q released (%s quiet, egress restored)", pid, st.comm, after)
				delete(a.contained, pid)
			}
			a.contMu.Unlock()
		}
	}
}

// pidAlive reports whether a process still exists. Signal 0 performs the kernel's
// permission/existence check without delivering a signal: a nil error or EPERM
// (exists but not ours to signal) both mean alive; ESRCH means gone.
func pidAlive(pid int32) bool {
	err := syscall.Kill(int(pid), 0)
	return err == nil || err == syscall.EPERM
}

// selfHeal restores a tampered sentinel file after letting the malicious write
// land, keeping the attacker's version as evidence. It owns the path's claim
// and heals again for as long as writes keep arriving during a heal. Every
// heal is audited (kind self_heal: healed | unchanged | failed:<err>).
func (a *App) selfHeal(path string, pid int32, comm string) {
	defer a.healWG.Done()
	for {
		a.healDelay() // let the write complete, then revert it
		res, err := a.healer.Heal(path)
		outcome := "unchanged"
		switch {
		case err != nil:
			outcome = "failed:" + err.Error()
			log.Printf("self-heal %q failed: %v", path, err)
		case res.Healed:
			outcome = "healed"
			log.Printf("SELF-HEALED %q (restored known-good; attacker version saved to %q)", path, res.Evidence)
		}
		if err := a.audit.Record(audit.Entry{
			Kind: audit.KindSelfHeal, Action: audit.KindSelfHeal, Outcome: outcome,
			PID: pid, Comm: comm, Path: path, Evidence: res.Evidence,
			Reason: fmt.Sprintf("self-heal of %s after a malicious write: %s", path, outcome),
		}); err != nil && err != audit.ErrDisabled {
			log.Printf("audit: %v", err)
		}
		if !a.healer.Finish(path) {
			return
		}
	}
}

// deadMansSwitch is the anti-blinding heartbeat: if the event stream was active
// and then goes silent, the agent's sensors may have been detached or disabled.
// Rule engines cannot detect the *absence* of telemetry; Phage can. It only
// warns when a previously-busy stream stops, so an idle host stays quiet.
func (a *App) deadMansSwitch(ctx context.Context) {
	const window = 30 * time.Second
	t := time.NewTicker(window)
	defer t.Stop()
	var last uint64
	var ewma float64 // smoothed events-per-window
	first := true
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.mu.Lock()
			now := a.nEvents
			a.mu.Unlock()
			delta := now - last
			last = now
			if first { // prime, don't judge the first window
				first = false
				ewma = float64(delta)
				continue
			}
			// Warn only if the stream was meaningfully active and just stopped.
			if delta == 0 && ewma >= 20 {
				log.Printf("CRITICAL self-defense: telemetry stopped unexpectedly (was ~%.0f events/%s, now 0) — sensors may be disabled or blinded", ewma, window)
			}
			ewma = 0.5*ewma + 0.5*float64(delta)
		}
	}
}

// labelFor is a coarse display bucket; the response matrix, not this, decides
// what to do about a score.
func labelFor(score float64) string {
	switch {
	case score >= 0.8:
		return "critical"
	case score >= 0.4:
		return "alert"
	default:
		return "notice"
	}
}

func reasons(v verdict.Verdict) string {
	if len(v.Reasons) == 0 {
		return "(no anomalous features)"
	}
	parts := make([]string, 0, len(v.Reasons))
	for _, r := range v.Reasons {
		parts = append(parts, r.Detail)
	}
	return strings.Join(parts, "; ")
}
