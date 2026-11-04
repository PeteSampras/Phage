// Command phage is the operator CLI. It is a thin client: it dials the running
// phaged daemon over its control socket and prints what it reports. The daemon
// owns all state.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"

	"github.com/AzozzALFiras/Phage/internal/analysis/baseline"
	"github.com/AzozzALFiras/Phage/internal/control"
	"github.com/AzozzALFiras/Phage/internal/logsafe"
)

var version = "dev"

func main() {
	sock := flag.String("control", "/run/phage.sock", "phaged control socket")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
		return
	}

	switch args[0] {
	case "version":
		fmt.Printf("phage %s\n", version)
	case "status":
		cmdStatus(*sock)
	case "events":
		cmdEvents(*sock, args[1:])
	case "thaw":
		cmdThaw(*sock, args[1:])
	case "baseline":
		os.Exit(cmdBaseline(args[1:], os.Stdout, os.Stderr))
	default:
		usage()
	}
}

func cmdStatus(sock string) {
	resp, err := control.Do(sock, control.Request{Cmd: "status"})
	check(err, resp)
	s := resp.Status
	fmt.Printf("mode=%s uptime=%s events=%d alerts=%d contained=%d\n",
		s.Mode, s.Uptime, s.Events, s.Alerts, s.Contained)
	fmt.Print(formatHealth(*s))
}

// formatHealth renders the sensor-health part of a status reply.
func formatHealth(s control.Status) string {
	drops := "unknown"
	switch {
	case s.Drops != nil:
		drops = strconv.FormatUint(*s.Drops, 10)
	case s.DropsError != "":
		drops = "unknown (" + logsafe.Clean(s.DropsError) + ")"
	}
	hb := s.LastHeartbeat
	if hb == "" {
		hb = "none yet"
	}
	out := fmt.Sprintf("drops=%s events_per_sec=%.2f enrich_lag_ms=%.2f last_heartbeat=%s\n",
		drops, s.EventsPerSec, s.EnrichLagMs, hb)
	out += fmt.Sprintf("baseline_state=%s baseline_sha256=%s baseline_overflow=%d unlearned=%d\n",
		orDash(s.BaselineState), orDash(s.BaselineSHA256), s.Overflow, s.Unlearned)
	if s.NoveltyPath != "" {
		out += fmt.Sprintf("novelty=%s rows=%d errors=%d\n", s.NoveltyPath, s.NoveltyRows, s.NoveltyErrors)
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// maxBaselineBytes bounds what `phage baseline` reads, so pointing it at the
// wrong file cannot exhaust memory.
const maxBaselineBytes = 512 << 20

// cmdBaseline is read-only review of baseline files, for use before switching
// a host from learn to alert: `show <file>` summarises one, `diff <old> <new>`
// compares two (e.g. a copy taken a week ago and the current file). It needs
// no daemon and writes nothing.
func cmdBaseline(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("baseline", flag.ContinueOnError)
	fs.SetOutput(stderr)
	maxValues := fs.Int("values", 20, "list at most this many values per change (0: all)")
	usage := func() int {
		fmt.Fprintln(stderr, "usage: phage baseline show <file> | phage baseline diff [-values n] <old> <new>")
		return 2
	}
	if len(args) == 0 {
		return usage()
	}
	sub := args[0]
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	files := fs.Args()
	switch {
	case sub == "show" && len(files) == 1:
		s, sum, err := readBaseline(files[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "%s sha256=%s\n", logsafe.Clean(files[0]), sum)
		baseline.WriteSummary(stdout, s)
		return 0
	case sub == "diff" && len(files) == 2:
		oldS, oldSum, err := readBaseline(files[0])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		newS, newSum, err := readBaseline(files[1])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "old %s sha256=%s\nnew %s sha256=%s\n", logsafe.Clean(files[0]), oldSum, logsafe.Clean(files[1]), newSum)
		fmt.Fprintln(stdout, "(values are as learned: ports and flags as numbers, program/pair/class names as hash ids)")
		baseline.WriteDiff(stdout, baseline.Diff(oldS, newS), *maxValues)
		return 0
	default:
		return usage()
	}
}

func readBaseline(path string) (baseline.Snapshot, string, error) {
	// O_NONBLOCK: a FIFO opens without waiting for a writer, and is then
	// refused below instead of hanging the command.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return baseline.Snapshot{}, "", err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return baseline.Snapshot{}, "", err
	} else if !fi.Mode().IsRegular() {
		return baseline.Snapshot{}, "", errors.New(logsafe.Clean(path) + ": not a regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxBaselineBytes+1))
	if err != nil {
		return baseline.Snapshot{}, "", fmt.Errorf("read %s: %w", path, err)
	}
	if len(b) > maxBaselineBytes {
		return baseline.Snapshot{}, "", errors.New(path + ": larger than 512 MiB; not a baseline")
	}
	s, err := baseline.ParseSnapshot(b)
	if err != nil {
		return baseline.Snapshot{}, "", fmt.Errorf("%s is not a valid baseline: %w", logsafe.Clean(path), err)
	}
	sum := sha256.Sum256(b)
	return s, hex.EncodeToString(sum[:]), nil
}

func cmdEvents(sock string, rest []string) {
	n := 20
	if len(rest) > 0 {
		if v, err := strconv.Atoi(rest[0]); err == nil {
			n = v
		}
	}
	resp, err := control.Do(sock, control.Request{Cmd: "events", N: n})
	check(err, resp)
	if len(resp.Alerts) == 0 {
		fmt.Println("no alerts recorded")
		return
	}
	for _, a := range resp.Alerts {
		// Reason and outcome carry attacker-chosen paths/names: escape them once
		// (logsafe.Clean) so they cannot inject lines or terminal sequences.
		fmt.Printf("%s  score=%.2f  requested=%s action=%s outcome=%s pid=%d comm=%q :: %s\n",
			a.Time, a.Score, a.Requested, a.Action, logsafe.Clean(a.Outcome), a.PID, a.Comm, logsafe.Clean(a.Reason))
	}
}

func cmdThaw(sock string, rest []string) {
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "usage: phage thaw <pid>")
		os.Exit(2)
	}
	pid, err := strconv.Atoi(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pid %q\n", rest[0])
		os.Exit(2)
	}
	resp, err := control.Do(sock, control.Request{Cmd: "thaw", PID: int32(pid)})
	check(err, resp)
	fmt.Println(resp.Message)
}

func check(err error, resp control.Response) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !resp.OK {
		fmt.Fprintln(os.Stderr, "error: "+resp.Error)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: phage [-control <socket>] <status|events [n]|thaw <pid>|baseline show <file>|baseline diff <old> <new>|version>")
	os.Exit(2)
}
