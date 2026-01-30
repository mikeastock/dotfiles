package server

import (
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
)

// Server is the Unix socket daemon.
type Server struct {
	sockPath string
	handler  *Handler
	listener net.Listener
	connID   atomic.Uint64
	wg       sync.WaitGroup
	done     chan struct{}
}

// NewServer creates a new server.
func NewServer(sockPath string, s *store.Store) *Server {
	return &Server{
		sockPath: sockPath,
		handler:  NewHandler(s),
		done:     make(chan struct{}),
	}
}

// ListenAndServe starts the server and blocks until Shutdown is called.
func (s *Server) ListenAndServe() error {
	os.Remove(s.sockPath)

	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return err
	}
	s.listener = ln

	os.Chmod(s.sockPath, 0666)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	os.Remove(s.sockPath)
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	connID := s.connID.Add(1)
	connIDStr := strconv.FormatUint(connID, 10)
	defer s.handler.RemoveConnection(connIDStr)

	codec := jsonrpc.NewCodec(conn, conn)

	for {
		req, err := codec.ReadRequest()
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			return
		}

		resp := s.handler.Handle(connIDStr, req)

		if req.ID != nil {
			if err := codec.WriteResponse(resp); err != nil {
				log.Printf("Write error: %v", err)
				return
			}
		}
	}
}
