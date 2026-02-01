package server

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
)

func TestServerStartStop(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	srv := NewServer(sockPath, store.New())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}

	codec := jsonrpc.NewCodec(conn, conn)
	err = codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "ping",
	})
	if err != nil {
		t.Fatalf("WriteRequest error: %v", err)
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse error: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	conn.Close()
	srv.Shutdown()

	select {
	case err := <-errCh:
		if err != nil && err != net.ErrClosed {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Server did not shut down")
	}
}

func TestServerConnectionCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	s := store.New()
	srv := NewServer(sockPath, s)
	go srv.ListenAndServe()
	defer srv.Shutdown()

	time.Sleep(50 * time.Millisecond)

	conn, _ := net.Dial("unix", sockPath)
	codec := jsonrpc.NewCodec(conn, conn)

	params, _ := json.Marshal(map[string]string{
		"session": "dev",
		"pane":    "%1",
		"agent":   "pi",
	})
	codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "register",
		Params: params,
	})
	codec.ReadResponse()

	sessions := s.ListBySession()
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}

	conn.Close()

	time.Sleep(100 * time.Millisecond)

	sessions = s.ListBySession()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after disconnect, got %d", len(sessions))
	}
}

func TestServerUpsertPersistsAfterDisconnect(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "tas-*.sock")
	if err != nil {
		t.Fatalf("CreateTemp error: %v", err)
	}
	sockPath := tmpFile.Name()
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	if err := os.Remove(sockPath); err != nil {
		t.Fatalf("Remove error: %v", err)
	}
	t.Cleanup(func() {
		os.Remove(sockPath)
	})

	s := store.New()
	srv := NewServer(sockPath, s)
	go srv.ListenAndServe()
	defer srv.Shutdown()

	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	codec := jsonrpc.NewCodec(conn, conn)

	params, _ := json.Marshal(map[string]string{
		"session": "dev",
		"pane":    "%1",
		"agent":   "codex",
		"state":   "working",
	})
	err = codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "upsert",
		Params: params,
	})
	if err != nil {
		t.Fatalf("WriteRequest error: %v", err)
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	sessions := s.ListBySession()
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	conn = nil

	time.Sleep(100 * time.Millisecond)

	sessions = s.ListBySession()
	if len(sessions) != 1 {
		t.Errorf("Expected 1 session after disconnect, got %d", len(sessions))
	}
}
