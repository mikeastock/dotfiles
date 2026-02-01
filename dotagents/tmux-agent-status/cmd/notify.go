package cmd

import (
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
)

var waitingEvents = map[string]bool{
	"agent-turn-complete": true,
	"agent_turn_complete": true,
	"turn/completed":      true,
	"turn_completed":      true,
}

var workingEvents = map[string]bool{
	"agent-turn-start": true,
	"agent_turn_start": true,
	"turn/started":     true,
	"turn_started":     true,
}

// RunNotify handles Codex notification payloads.
func RunNotify(args []string) error {
	var payload string
	if len(args) > 0 {
		payload = args[0]
	} else {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		payload = strings.TrimSpace(sb.String())
	}

	if payload == "" {
		return nil
	}

	var notification map[string]any
	if err := json.Unmarshal([]byte(payload), &notification); err != nil {
		return nil
	}

	eventType := extractEventType(notification)

	var state string
	if waitingEvents[eventType] {
		state = "waiting"
	} else if workingEvents[eventType] {
		state = "working"
	} else {
		return nil
	}

	session, pane := getTmuxInfo()
	if session == "" {
		return nil
	}

	sockPath := DefaultSocketPath()
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second))
	codec := jsonrpc.NewCodec(conn, conn)

	params, _ := json.Marshal(map[string]string{
		"session": session,
		"pane":    pane,
		"agent":   "codex",
		"state":   state,
	})

	codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "upsert",
		Params: params,
	})

	return nil
}

func extractEventType(notification map[string]any) string {
	if t, ok := notification["type"].(string); ok {
		return t
	}
	if t, ok := notification["method"].(string); ok {
		return t
	}
	if event, ok := notification["event"].(map[string]any); ok {
		if t, ok := event["type"].(string); ok {
			return t
		}
		if t, ok := event["method"].(string); ok {
			return t
		}
	}
	return ""
}

func getTmuxInfo() (session, pane string) {
	cmd := exec.Command("tmux", "display-message", "-p", "#S\n#{pane_id}")
	out, err := cmd.Output()
	if err != nil {
		return "", ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) >= 1 {
		session = lines[0]
	}
	if len(lines) >= 2 {
		pane = lines[1]
	}
	return
}
