package control

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"os"
	"time"
)

// Handler is implemented by the daemon to answer control requests.
type Handler interface {
	Status() Status
	RecentAlerts(n int) []Alert
	Thaw(pid int32) error
}

// Server accepts CLI connections on a Unix socket and dispatches to a Handler.
type Server struct {
	ln net.Listener
}

// Serve starts a control server on the Unix socket at path. An empty path
// disables the server (returns nil, nil). The server stops when ctx is done.
//
// The socket is created 0600 from the start (listenPrivate binds under umask
// 077, so there is no window in which it is world-connectable), and every
// connection's peer credentials (SO_PEERCRED) must be uid 0 — `phage thaw`
// releases a contained process, so only root may drive it.
func Serve(ctx context.Context, path string, h Handler) (*Server, error) {
	if path == "" {
		return nil, nil
	}
	_ = os.Remove(path) // clear a stale socket from a previous run
	ln, err := listenPrivate(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil { // belt and braces
		ln.Close()
		return nil, err
	}

	s := &Server{ln: ln}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	go s.accept(h)
	return s, nil
}

func (s *Server) accept(h Handler) {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		if err := checkPeer(conn); err != nil {
			log.Printf("control socket: rejected connection: %v", err)
			go reject(conn)
			continue
		}
		go serveConn(conn, h)
	}
}

// reject answers a disallowed peer with "permission denied". It first reads
// (and discards, bounded) the request, so the client gets the answer rather
// than a broken pipe from writing into an already-closed socket. Nothing it
// sends is acted on.
func reject(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var discard json.RawMessage
	_ = json.NewDecoder(io.LimitReader(conn, 4096)).Decode(&discard)
	writeResp(conn, Response{OK: false, Error: "permission denied"})
}

func serveConn(conn net.Conn, h Handler) {
	defer conn.Close()
	// A client that connects and never sends must not pin a goroutine forever.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		writeResp(conn, Response{OK: false, Error: "bad request"})
		return
	}
	writeResp(conn, dispatch(req, h))
}

func dispatch(req Request, h Handler) Response {
	switch req.Cmd {
	case "status":
		st := h.Status()
		return Response{OK: true, Status: &st}
	case "events":
		n := req.N
		if n <= 0 {
			n = 20
		}
		return Response{OK: true, Alerts: h.RecentAlerts(n)}
	case "thaw":
		if err := h.Thaw(req.PID); err != nil {
			return Response{OK: false, Error: err.Error()}
		}
		return Response{OK: true, Message: "thawed and released"}
	default:
		return Response{OK: false, Error: "unknown command: " + req.Cmd}
	}
}

// Close stops the server and removes the socket.
func (s *Server) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

func writeResp(conn net.Conn, r Response) {
	_ = json.NewEncoder(conn).Encode(r)
}
