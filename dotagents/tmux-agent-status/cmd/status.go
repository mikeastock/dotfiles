package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/render"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

// RunStatus queries the daemon and prints tmux-formatted output.
func RunStatus(args []string) error {
	sockPath := DefaultSocketPath()

	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second))

	codec := jsonrpc.NewCodec(conn, conn)
	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "status",
	}); err != nil {
		return nil
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		return nil
	}

	if resp.Error != nil {
		return nil
	}

	var result struct {
		Sessions []types.SessionStatus `json:"sessions"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil
	}

	output := render.Tmux(result.Sessions)
	if output != "" {
		fmt.Print(output)
	}

	return nil
}
