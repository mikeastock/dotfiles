package store

import (
	"testing"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

func TestStoreRegisterAndGet(t *testing.T) {
	s := New()

	id := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)
	if id == "" {
		t.Fatal("Expected non-empty agent ID")
	}

	agent, ok := s.Get(id)
	if !ok {
		t.Fatal("Expected to find agent")
	}
	if agent.Session != "dev" {
		t.Errorf("Session = %s, want dev", agent.Session)
	}
	if agent.Type != types.AgentPi {
		t.Errorf("Type = %s, want pi", agent.Type)
	}
}

func TestStoreUpdate(t *testing.T) {
	s := New()
	id := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)

	ok := s.Update(id, types.StateWorking)
	if !ok {
		t.Fatal("Update should succeed")
	}

	agent, _ := s.Get(id)
	if agent.State != types.StateWorking {
		t.Errorf("State = %s, want working", agent.State)
	}
}

func TestStoreUnregister(t *testing.T) {
	s := New()
	id := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)

	s.Unregister(id)

	_, ok := s.Get(id)
	if ok {
		t.Error("Agent should be removed after unregister")
	}
}

func TestStoreRemoveByConnection(t *testing.T) {
	s := New()
	id1 := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)
	id2 := s.Register("conn2", "dev", "%2", types.AgentCodex, types.StateWorking)

	s.RemoveByConnection("conn1")

	_, ok1 := s.Get(id1)
	_, ok2 := s.Get(id2)

	if ok1 {
		t.Error("Agent from conn1 should be removed")
	}
	if !ok2 {
		t.Error("Agent from conn2 should still exist")
	}
}

func TestStoreListBySession(t *testing.T) {
	s := New()
	s.Register("conn1", "dev", "%1", types.AgentPi, types.StateWorking)
	s.Register("conn2", "dev", "%2", types.AgentCodex, types.StateWaiting)
	s.Register("conn3", "staging", "%1", types.AgentPi, types.StateIdle)

	sessions := s.ListBySession()

	if len(sessions) != 2 {
		t.Fatalf("Expected 2 sessions, got %d", len(sessions))
	}

	if sessions[0].Name != "dev" {
		t.Errorf("First session = %s, want dev", sessions[0].Name)
	}
	if sessions[1].Name != "staging" {
		t.Errorf("Second session = %s, want staging", sessions[1].Name)
	}

	if len(sessions[0].Agents) != 2 {
		t.Errorf("Dev agents = %d, want 2", len(sessions[0].Agents))
	}
}
