package types

import "testing"

func TestAgentStateValid(t *testing.T) {
	tests := []struct {
		state AgentState
		want  bool
	}{
		{StateIdle, true},
		{StateWorking, true},
		{StateWaiting, true},
		{AgentState("unknown"), false},
		{AgentState(""), false},
	}

	for _, tt := range tests {
		if got := tt.state.Valid(); got != tt.want {
			t.Errorf("AgentState(%q).Valid() = %v, want %v", tt.state, got, tt.want)
		}
	}
}

func TestAgentTypeName(t *testing.T) {
	if AgentPi.String() != "pi" {
		t.Errorf("AgentPi.String() = %s, want pi", AgentPi.String())
	}
	if AgentCodex.String() != "codex" {
		t.Errorf("AgentCodex.String() = %s, want codex", AgentCodex.String())
	}
}
