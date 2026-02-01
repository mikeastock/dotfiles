package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
)

// RunRegister registers an agent (for testing).
func RunRegister(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: register <session> <agent-type> [pane]")
	}

	session := args[0]
	agentType := args[1]
	pane := ""
	if len(args) > 2 {
		pane = args[2]
	}

	conn, err := connectDaemon()
	if err != nil {
		return err
	}
	defer conn.Close()

	codec := jsonrpc.NewCodec(conn, conn)
	params, _ := json.Marshal(map[string]string{
		"session": session,
		"pane":    pane,
		"agent":   agentType,
	})

	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "register",
		Params: params,
	}); err != nil {
		return err
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("register failed: %s", resp.Error.Message)
	}

	fmt.Println(string(resp.Result))
	return nil
}

// RunUpdate updates agent state (for testing).
func RunUpdate(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: update <agent-id> <state>")
	}

	agentID := args[0]
	state := args[1]

	conn, err := connectDaemon()
	if err != nil {
		return err
	}
	defer conn.Close()

	codec := jsonrpc.NewCodec(conn, conn)
	params, _ := json.Marshal(map[string]string{
		"agent_id": agentID,
		"state":    state,
	})

	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "update",
		Params: params,
	}); err != nil {
		return err
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("update failed: %s", resp.Error.Message)
	}

	fmt.Println("updated")
	return nil
}

// RunUnregister removes an agent by ID (for testing).
func RunUnregister(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: unregister <agent-id>")
	}

	agentID := args[0]

	conn, err := connectDaemon()
	if err != nil {
		return err
	}
	defer conn.Close()

	codec := jsonrpc.NewCodec(conn, conn)
	params, _ := json.Marshal(map[string]string{
		"agent_id": agentID,
	})

	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "unregister",
		Params: params,
	}); err != nil {
		return err
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("unregister failed: %s", resp.Error.Message)
	}

	fmt.Println("unregistered")
	return nil
}

// RunList shows all agents as JSON.
func RunList(args []string) error {
	conn, err := connectDaemon()
	if err != nil {
		return err
	}
	defer conn.Close()

	codec := jsonrpc.NewCodec(conn, conn)
	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "status",
	}); err != nil {
		return err
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return fmt.Errorf("list failed: %s", resp.Error.Message)
	}

	var data any
	json.Unmarshal(resp.Result, &data)
	out, _ := json.MarshalIndent(data, "", "  ")
	fmt.Println(string(out))
	return nil
}

func connectDaemon() (net.Conn, error) {
	sockPath := DefaultSocketPath()
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to daemon (is it running?)")
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn, nil
}
