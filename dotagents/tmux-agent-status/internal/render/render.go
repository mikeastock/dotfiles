package render

import (
	"strings"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

const (
	colorYellow = "#[fg=yellow]"
	colorGreen  = "#[fg=green]"
	colorDim    = "#[fg=colour244]"
	colorReset  = "#[fg=default]"

	symbolWaiting = "◉"
	symbolWorking = "●"
	symbolIdle    = "○"
)

// Tmux renders session statuses as tmux-formatted output.
func Tmux(sessions []types.SessionStatus) string {
	if len(sessions) == 0 {
		return ""
	}

	var parts []string
	for _, session := range sessions {
		indicators := renderIndicators(session.Agents)
		if indicators != "" {
			parts = append(parts, session.Name+" "+indicators+colorReset)
		}
	}

	return strings.Join(parts, "  ")
}

func renderIndicators(agents []types.Agent) string {
	hasWaiting := false
	hasWorking := false
	hasIdle := false

	for _, agent := range agents {
		switch agent.State {
		case types.StateWaiting:
			hasWaiting = true
		case types.StateWorking:
			hasWorking = true
		case types.StateIdle:
			hasIdle = true
		}
	}

	var sb strings.Builder
	if hasWaiting {
		sb.WriteString(colorYellow)
		sb.WriteString(symbolWaiting)
	}
	if hasWorking {
		sb.WriteString(colorGreen)
		sb.WriteString(symbolWorking)
	}
	if hasIdle {
		sb.WriteString(colorDim)
		sb.WriteString(symbolIdle)
	}

	return sb.String()
}
