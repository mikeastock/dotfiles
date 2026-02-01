package store

import (
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

// Store holds the in-memory registry of agents.
type Store struct {
	mu     sync.RWMutex
	agents map[string]*agentEntry
}

type agentEntry struct {
	connID string
	agent  types.Agent
}

// New creates a new empty store.
func New() *Store {
	return &Store{
		agents: make(map[string]*agentEntry),
	}
}

// Register adds a new agent and returns its ID.
func (s *Store) Register(connID, session, pane string, agentType types.AgentType, state types.AgentState) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := generateID()
	s.agents[id] = &agentEntry{
		connID: connID,
		agent: types.Agent{
			ID:      id,
			Session: session,
			Pane:    pane,
			Type:    agentType,
			State:   state,
		},
	}
	return id
}

// Upsert updates an agent by session/pane/type or creates a new one.
func (s *Store) Upsert(session, pane string, agentType types.AgentType, state types.AgentState) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, entry := range s.agents {
		if entry.agent.Session == session && entry.agent.Pane == pane && entry.agent.Type == agentType {
			entry.agent.State = state
			return id
		}
	}

	id := generateID()
	s.agents[id] = &agentEntry{
		connID: "",
		agent: types.Agent{
			ID:      id,
			Session: session,
			Pane:    pane,
			Type:    agentType,
			State:   state,
		},
	}
	return id
}

// Get retrieves an agent by ID.
func (s *Store) Get(id string) (types.Agent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.agents[id]
	if !ok {
		return types.Agent{}, false
	}
	return entry.agent, true
}

// Update changes the state of an existing agent.
func (s *Store) Update(id string, state types.AgentState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.agents[id]
	if !ok {
		return false
	}
	entry.agent.State = state
	return true
}

// Unregister removes an agent by ID.
func (s *Store) Unregister(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.agents, id)
}

// RemoveByConnection removes all agents for a given connection ID.
func (s *Store) RemoveByConnection(connID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, entry := range s.agents {
		if entry.connID == connID {
			delete(s.agents, id)
		}
	}
}

// ListBySession returns all agents grouped by session, sorted alphabetically.
func (s *Store) ListBySession() []types.SessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bySession := make(map[string][]types.Agent)
	for _, entry := range s.agents {
		bySession[entry.agent.Session] = append(bySession[entry.agent.Session], entry.agent)
	}

	var sessions []types.SessionStatus
	for name, agents := range bySession {
		sessions = append(sessions, types.SessionStatus{
			Name:   name,
			Agents: agents,
		})
	}

	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].Name < sessions[j].Name
	})

	return sessions
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}
