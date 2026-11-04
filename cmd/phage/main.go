// Command phage is the operator CLI. It is a thin client: it dials the running
// phaged daemon over its control socket and prints what it reports. The daemon
// owns all state.
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"

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
	fmt.Fprintln(os.Stderr, "usage: phage [-control <socket>] <status|events [n]|thaw <pid>|version>")
	os.Exit(2)
}
