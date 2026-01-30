package render

import (
	"testing"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

func TestRenderEmpty(t *testing.T) {
	out := Tmux(nil)
	if out != "" {
		t.Errorf("Expected empty, got %q", out)
	}
}

func TestRenderSingleWorking(t *testing.T) {
	sessions := []types.SessionStatus{
		{
			Name: "dev",
			Agents: []types.Agent{
				{State: types.StateWorking},
			},
		},
	}
	out := Tmux(sessions)
	want := "dev #[fg=green]●#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}

func TestRenderSingleWaiting(t *testing.T) {
	sessions := []types.SessionStatus{
		{
			Name: "dev",
			Agents: []types.Agent{
				{State: types.StateWaiting},
			},
		},
	}
	out := Tmux(sessions)
	want := "dev #[fg=yellow]◉#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}

func TestRenderSingleIdle(t *testing.T) {
	sessions := []types.SessionStatus{
		{
			Name: "dev",
			Agents: []types.Agent{
				{State: types.StateIdle},
			},
		},
	}
	out := Tmux(sessions)
	want := "dev #[fg=colour244]○#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}

func TestRenderCombinedIndicators(t *testing.T) {
	sessions := []types.SessionStatus{
		{
			Name: "dev",
			Agents: []types.Agent{
				{State: types.StateWorking},
				{State: types.StateWaiting},
				{State: types.StateIdle},
			},
		},
	}
	out := Tmux(sessions)
	want := "dev #[fg=yellow]◉#[fg=green]●#[fg=colour244]○#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}

func TestRenderMultipleSessions(t *testing.T) {
	sessions := []types.SessionStatus{
		{
			Name: "alpha",
			Agents: []types.Agent{
				{State: types.StateWorking},
			},
		},
		{
			Name: "beta",
			Agents: []types.Agent{
				{State: types.StateWaiting},
			},
		},
	}
	out := Tmux(sessions)
	want := "alpha #[fg=green]●#[fg=default]  beta #[fg=yellow]◉#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}

func TestRenderDeduplicatesStates(t *testing.T) {
	sessions := []types.SessionStatus{
		{
			Name: "dev",
			Agents: []types.Agent{
				{State: types.StateWorking},
				{State: types.StateWorking},
			},
		},
	}
	out := Tmux(sessions)
	want := "dev #[fg=green]●#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}
