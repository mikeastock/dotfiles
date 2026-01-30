package types

// AgentState represents the current state of an agent.
type AgentState string

const (
	StateIdle    AgentState = "idle"
	StateWorking AgentState = "working"
	StateWaiting AgentState = "waiting"
)

// Valid returns true if the state is a recognized value.
func (s AgentState) Valid() bool {
	switch s {
	case StateIdle, StateWorking, StateWaiting:
		return true
	default:
		return false
	}
}

// AgentType represents the type of agent.
type AgentType string

const (
	AgentPi    AgentType = "pi"
	AgentCodex AgentType = "codex"
)

func (a AgentType) String() string {
	return string(a)
}

// Agent holds registration info for a connected agent.
type Agent struct {
	ID      string     `json:"agent_id"`
	Session string     `json:"session"`
	Pane    string     `json:"pane,omitempty"`
	Type    AgentType  `json:"agent"`
	State   AgentState `json:"state"`
}

// SessionStatus aggregates agent states for a tmux session.
type SessionStatus struct {
	Name   string  `json:"name"`
	Agents []Agent `json:"agents"`
}
