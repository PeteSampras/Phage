// Package app wires the pipeline together and owns the daemon's run loop. It is
// the one place that knows about every stage; each stage still knows only its
// neighbours. Keeping the wiring here lets cmd/phaged stay a thin entrypoint.
package app

import (
	"context"
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
	freezer       *contain.Freezer
	netq          *netquarantine.Manager
	healer        *selfheal.Store
	audit         *audit.Writer

	meta Meta

	// Identity used to trust events — never the attacker-chosen comm. selfPID is
	// the agent's own tgid; getppid returns its current parent (consulted only
	// when dev.trust_launcher_signals is on). exeOf resolves /proc/<pid>/exe
	// (swappable in tests).
	selfPID int32
	getppid func() int
	proc    procView      // /proc reads (fake in tests)
	sshd    *sshdIdentity // host sshd binaries by inode

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

	// Acting features. Each arms only when mode is enforce AND its own
	// `enforcement:` key is on (config.Armed); config.Validate already refused
	// any other combination at startup, and Armed re-checks the mode here so a
	// config that skipped Validate still cannot arm anything outside enforce.

	// armed / failed collect what actually armed and what was requested but
	// could not arm, for the single ENFORCEMENT ARMED line + audit record below.
	var armed, failed []string

	// Honeytokens (deception.honeytokens; alert or enforce): plant decoy
	// credential files and alert on any read. Decoys a previous run left behind
	// (e.g. after a crash) are re-adopted from the record next to the baseline.
	if a.cfg.Armed(config.FeatureHoneytokens) {
		ht := honeytoken.New(filepath.Join(filepath.Dir(a.cfg.StatePath), "honeytokens.json"), honeytoken.Decoys)
		planted, err := ht.Seed()
		switch {
		case err != nil:
			log.Printf("honeytokens: %v", err)
			failed = append(failed, config.FeatureHoneytokens)
		case len(planted) == 0:
			log.Printf("honeytokens: none planted (real files at every decoy path)")
			failed = append(failed, config.FeatureHoneytokens)
		default:
			if err := sensor.SetHoneytokens(honeytoken.Inodes(planted)); err != nil {
				log.Printf("honeytokens: %v", err)
				ht.Shutdown(planted)
				failed = append(failed, config.FeatureHoneytokens)
			} else {
				defer ht.Shutdown(planted)
				armed = append(armed, config.FeatureHoneytokens)
				adopted := 0
				for _, p := range planted {
					if p.Adopted {
						adopted++
					}
				}
				log.Printf("honeytokens planted: %d decoys (%d re-adopted from a previous run) — any read of one is a high-confidence alert", len(planted), adopted)
			}
		}
	}

	// Tamper-resistance: deny signals that would kill the agent. Loaded as a
	// separate eBPF-LSM object so a kernel without BPF LSM still runs the agent.
	if a.cfg.Armed(config.FeatureSelfProtect) {
		if !selfprotect.Available() {
			log.Printf("self-protection requested (enforcement.self_protect) but BPF LSM is not active; running without it")
			failed = append(failed, config.FeatureSelfProtect)
		} else {
			objPath := filepath.Join(filepath.Dir(a.objPath), "selfprotect.bpf.o")
			// The LSM always allows pid 1 and the agent itself; the launcher slot
			// gets a real pid only when dev.trust_launcher_signals says so (pid 1
			// otherwise, which adds nothing).
			launcher := uint32(1)
			if a.cfg.Dev.TrustLauncherSignals {
				launcher = uint32(os.Getppid())
			}
			g, err := selfprotect.Arm(objPath, uint32(os.Getpid()), launcher)
			if err != nil {
				log.Printf("self-protection: %v; running without it", err)
				failed = append(failed, config.FeatureSelfProtect)
			} else {
				defer g.Close()
				armed = append(armed, config.FeatureSelfProtect)
				log.Printf("self-protection ARMED: signals that would kill the agent are denied (except from pid 1); systemctl stop and reboot still work")
			}
		}
	}

	// Per-process network quarantine (the reversible isolate rung used for
	// egress/C2 verdicts). Optional: if it can't load, egress verdicts fall back
	// to freeze — but only if freeze is armed too; otherwise they alert.
	if a.cfg.Armed(config.FeatureIsolate) {
		nqObj := filepath.Join(filepath.Dir(a.objPath), "netquarantine.bpf.o")
		if nq, err := netquarantine.New(nqObj); err != nil {
			log.Printf("network quarantine unavailable: %v (egress verdicts will freeze if freeze is armed, else alert)", err)
			failed = append(failed, config.FeatureIsolate)
		} else {
			a.netq = nq
			defer nq.Close()
			armed = append(armed, config.FeatureIsolate)
		}
	}

	// Freeze has nothing to load: the cgroup freezer is driven on demand.
	if a.cfg.Armed(config.FeatureFreeze) {
		armed = append(armed, config.FeatureFreeze)
	}

	// Self-healing: snapshot the sentinel files now, restore them after a
	// malicious write. Only files snapshotted here are ever healed.
	if a.cfg.Armed(config.FeatureSelfHeal) {
		if h, err := selfheal.New("/var/lib/phage/quarantine"); err != nil {
			log.Printf("self-heal: %v; running without it", err)
			failed = append(failed, config.FeatureSelfHeal)
		} else {
			a.healer = h
			n := a.healer.SnapshotAll(selfheal.DefaultSentinels())
			log.Printf("self-heal armed: %d sentinel file(s) snapshotted (restored on malicious write)", n)
			armed = append(armed, config.FeatureSelfHeal)
		}
	}

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
	// Escalation / de-dup: if this process is already contained at an equal or
	// stronger rung, just refresh its lease and record the alert — don't
	// re-actuate or spam the log. A strictly stronger action escalates.
	a.contMu.Lock()
	if st := a.contained[ev.PID]; st != nil && response.Rung(want) <= response.Rung(st.rung) {
		st.last = time.Now()
		a.contMu.Unlock()
		a.mu.Lock()
		a.nAlerts++
		a.mu.Unlock()
		return
	}
	a.contMu.Unlock()

	parent := ev.ParentComm
	if parent == "" && len(ev.Lineage) > 0 {
		parent = ev.Lineage[0].Comm
	}
	// The matrix says what the verdict would justify; the config says what the
	// operator has allowed. Downgrade a rung that is not armed to an alert.
	want, gateNote := a.gate(want)

	reason := reasons(v)
	if gateNote != "" {
		reason = fmt.Sprintf("%s [%s]", reason, gateNote)
	}
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
		reason = fmt.Sprintf("%s (wrote %q)", reason, ev.File.Path)
	}
	if ev.Kind == kind.Enable && ev.EnableOp != "" {
		reason = fmt.Sprintf("%s (op: %q)", reason, ev.EnableOp)
	}
	// Every attacker-influenced string (comm, parent, the reason — which embeds
	// paths and executable names) is printed with %q, so a crafted name holding a
	// newline or control bytes cannot forge an extra journal line.
	log.Printf("%s score=%.2f action=%s pid=%d comm=%q parent=%q uid=%d->euid=%d interactive=%t :: reason=%q",
		strings.ToUpper(labelFor(v.Score)), v.Score, want,
		ev.PID, ev.Comm, parent, ev.Creds.UID, ev.Creds.EUID, ev.Session.Interactive, reason)

	_ = a.audit.Record(audit.Entry{
		Kind: audit.KindResponse, Action: string(want), Score: v.Score, PID: ev.PID, Comm: ev.Comm, Reason: reason,
	})

	// Actuate the chosen rung.
	contained := false
	switch want {
	case action.Isolate:
		if ok, why := containmentSafe(ev, a.selfPID, a.proc, a.sshd); !ok {
			log.Printf("CONTAIN pid=%d comm=%q ISOLATE SKIPPED (%s) — alert only", ev.PID, ev.Comm, why)
			want = action.Notify
		} else if a.netq != nil {
			if err := a.netq.Isolate(ev.PID); err != nil {
				log.Printf("ISOLATE pid=%d failed: %v", ev.PID, err)
			} else {
				contained = true
				log.Printf("CONTAIN pid=%d comm=%q ISOLATED (egress severed, process alive, reversible)", ev.PID, ev.Comm)
			}
		} else if a.cfg.Armed(config.FeatureFreeze) { // isolation armed but failed to load — fall back to freeze
			want = action.Freeze
		} else {
			want = action.Notify
			log.Printf("ISOLATE pid=%d unavailable (network quarantine not loaded) and freeze not armed — alert only", ev.PID)
		}
	}
	if want == action.Freeze && a.cfg.Armed(config.FeatureFreeze) {
		if ok, why := containmentSafe(ev, a.selfPID, a.proc, a.sshd); !ok {
			log.Printf("CONTAIN pid=%d comm=%q SKIPPED (%s) — alert only", ev.PID, ev.Comm, why)
		} else if err := a.freezer.Freeze(ev.PID); err != nil {
			log.Printf("CONTAIN pid=%d failed: %v", ev.PID, err)
		} else {
			contained = true
			log.Printf("CONTAIN pid=%d comm=%q FROZEN (process tree quarantined, reversible)", ev.PID, ev.Comm)
		}
	}

	// Self-heal a malicious write to a snapshotted sentinel file. Gated on the
	// score crossing the containment threshold (the write is judged malicious),
	// independent of the process-containment rung above.
	if ev.Kind == kind.FileWrite && v.Score >= a.cfg.Thresholds.Contain &&
		a.cfg.Armed(config.FeatureSelfHeal) && a.healer != nil && a.healer.Watched(ev.File.Path) {
		// The event's path was resolved in the WRITER's mount namespace: only a
		// writer in the host's namespace can have touched the host file we
		// snapshotted. Checked now, while the writer is most likely alive; a
		// writer already gone is not healed (the alert stands).
		if ok, why := sameMountNS(a.proc, ev.PID); !ok {
			log.Printf("SELF-HEAL %q SKIPPED (%s) — alert only", ev.File.Path, why)
		} else if a.healer.Claim(ev.File.Path) { // one pending heal per path, however many writes
			go a.selfHeal(ev.File.Path)
		}
	}

	if contained {
		a.contMu.Lock()
		a.contained[ev.PID] = &contState{rung: want, last: time.Now(), comm: ev.Comm}
		a.contMu.Unlock()
	}

	a.mu.Lock()
	a.nAlerts++
	if contained {
		a.nContained++
	}
	a.recent = append(a.recent, control.Alert{
		Time: time.Now().UTC().Format(time.RFC3339), Score: v.Score,
		Action: string(want), PID: ev.PID, Comm: ev.Comm, Reason: reason,
	})
	if len(a.recent) > a.recentLimit {
		a.recent = a.recent[len(a.recent)-a.recentLimit:]
	}
	a.mu.Unlock()
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
	detail := fmt.Sprintf("attempt to tamper with the Phage agent: %s by %q (pid %d) — monitor blinding/kill attempt",
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
	detail := fmt.Sprintf("read a planted honeytoken decoy %q — near-certain credential theft / intruder snooping", ev.File.Path)
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
// land, keeping the attacker's version as evidence.
func (a *App) selfHeal(path string) {
	defer a.healer.Release(path)
	time.Sleep(250 * time.Millisecond) // let the write complete, then revert it
	q, err := a.healer.Heal(path)
	if err != nil {
		log.Printf("self-heal %q failed: %v", path, err)
		return
	}
	if q != "" {
		log.Printf("SELF-HEALED %q (restored known-good; attacker version saved to %q)", path, q)
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
