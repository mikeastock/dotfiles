package server

import (
	"encoding/json"
	"testing"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

func TestHandlePing(t *testing.T) {
	h := NewHandler(store.New())

	req := &jsonrpc.Request{
		ID:     1,
		Method: "ping",
	}

	resp := h.Handle("conn1", req)

	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	var result map[string]string
	json.Unmarshal(resp.Result, &result)
	if result["pong"] != "ok" {
		t.Errorf("Expected pong, got %v", result)
	}
}

func TestHandleRegister(t *testing.T) {
	h := NewHandler(store.New())

	params, _ := json.Marshal(map[string]string{
		"session": "dev",
		"pane":    "%1",
		"agent":   "pi",
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "register",
		Params: params,
	}

	resp := h.Handle("conn1", req)

	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	var result map[string]string
	json.Unmarshal(resp.Result, &result)
	if result["agent_id"] == "" {
		t.Error("Expected agent_id in response")
	}
}

func TestHandleUpdate(t *testing.T) {
	s := store.New()
	h := NewHandler(s)

	agentID := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)

	params, _ := json.Marshal(map[string]string{
		"state": "working",
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "update",
		Params: params,
	}

	h.SetAgentID("conn1", agentID)

	resp := h.Handle("conn1", req)

	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	agent, _ := s.Get(agentID)
	if agent.State != types.StateWorking {
		t.Errorf("State = %s, want working", agent.State)
	}
}

func TestHandleUpdateByAgentID(t *testing.T) {
	s := store.New()
	h := NewHandler(s)

	agentID := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)

	params, _ := json.Marshal(map[string]string{
		"agent_id": agentID,
		"state":    "working",
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "update",
		Params: params,
	}

	resp := h.Handle("conn2", req)

	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	agent, _ := s.Get(agentID)
	if agent.State != types.StateWorking {
		t.Errorf("State = %s, want working", agent.State)
	}
}

func TestHandleUpdateUnknownAgentID(t *testing.T) {
	s := store.New()
	h := NewHandler(s)

	params, _ := json.Marshal(map[string]string{
		"agent_id": "unknown",
		"state":    "working",
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "update",
		Params: params,
	}

	resp := h.Handle("conn1", req)

	if resp.Error == nil {
		t.Fatal("Expected error for unknown agent_id")
	}
}

func TestHandleUnregisterByAgentID(t *testing.T) {
	s := store.New()
	h := NewHandler(s)

	agentID := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)

	params, _ := json.Marshal(map[string]string{
		"agent_id": agentID,
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "unregister",
		Params: params,
	}

	resp := h.Handle("conn2", req)

	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	if _, ok := s.Get(agentID); ok {
		t.Fatal("Expected agent to be unregistered")
	}
}

func TestHandleUnregisterUnknownAgentID(t *testing.T) {
	s := store.New()
	h := NewHandler(s)

	params, _ := json.Marshal(map[string]string{
		"agent_id": "unknown",
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "unregister",
		Params: params,
	}

	resp := h.Handle("conn1", req)

	if resp.Error == nil {
		t.Fatal("Expected error for unknown agent_id")
	}
}

func TestHandleStatus(t *testing.T) {
	s := store.New()
	h := NewHandler(s)

	s.Register("conn1", "dev", "%1", types.AgentPi, types.StateWorking)

	req := &jsonrpc.Request{
		ID:     1,
		Method: "status",
	}

	resp := h.Handle("conn1", req)

	if resp.Error != nil {
		t.Fatalf("Unexpected error: %v", resp.Error)
	}

	var result struct {
		Sessions []types.SessionStatus `json:"sessions"`
	}
	json.Unmarshal(resp.Result, &result)

	if len(result.Sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(result.Sessions))
	}
}

func TestHandleMethodNotFound(t *testing.T) {
	h := NewHandler(store.New())

	req := &jsonrpc.Request{
		ID:     1,
		Method: "unknown",
	}

	resp := h.Handle("conn1", req)

	if resp.Error == nil {
		t.Fatal("Expected error")
	}
	if resp.Error.Code != jsonrpc.ErrMethodNotFound {
		t.Errorf("Code = %d, want %d", resp.Error.Code, jsonrpc.ErrMethodNotFound)
	}
}
