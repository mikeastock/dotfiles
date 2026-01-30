package main

import (
	"fmt"
	"os"

	"github.com/mikeastock/dotagents/tmux-agent-status/cmd"
)

func main() {
	if len(os.Args) < 2 {
		os.Args = append(os.Args, "status")
	}

	command := os.Args[1]
	args := os.Args[2:]

	var err error
	switch command {
	case "daemon":
		err = cmd.RunDaemon(args)
	case "status":
		err = cmd.RunStatus(args)
	case "notify":
		err = cmd.RunNotify(args)
	case "register":
		err = cmd.RunRegister(args)
	case "update":
		err = cmd.RunUpdate(args)
	case "unregister":
		err = cmd.RunUnregister(args)
	case "list":
		err = cmd.RunList(args)
	case "help", "-h", "--help":
		printHelp()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`agent-status - AI agent status for tmux

Commands:
  daemon      Start the status daemon
  status      Query and render status (default)
  notify      Handle Codex notification (for --notify-command)
  register    Register an agent (debug)
  update      Update agent state (debug)
  unregister  Unregister an agent (debug)
  list        List all agents as JSON (debug)

Socket: ~/.config/agents/agent-status.sock`)
}
