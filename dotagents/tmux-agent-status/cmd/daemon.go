package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/server"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
)

// DefaultSocketPath returns the default socket path.
func DefaultSocketPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agents", "agent-status.sock")
}

// RunDaemon starts the daemon server.
func RunDaemon(args []string) error {
	sockPath := DefaultSocketPath()

	if err := os.MkdirAll(filepath.Dir(sockPath), 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	s := store.New()
	srv := server.NewServer(sockPath, s)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		srv.Shutdown()
	}()

	fmt.Printf("Listening on %s\n", sockPath)
	return srv.ListenAndServe()
}
