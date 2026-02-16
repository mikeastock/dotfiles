# tmux-agent-status Go Daemon Implementation Plan

> REQUIRED SUB-SKILL: Use superpowers:executing-plans skill to implement this plan task-by-task.

**Goal:** Replace bash/python scripts with a single Go binary daemon using JSON-RPC over Unix socket for multi-agent status tracking.

**Architecture:** A long-running daemon listens on `~/.config/agents/agent-status.sock`. Agents (Pi extension, Codex bridge) connect and send state updates. Connection close = agent death (no PID polling). The `status` subcommand queries the daemon and renders tmux output.

**Tech Stack:** Go 1.21+, bufio for NDJSON, net/unix for sockets, encoding/json for JSON-RPC

---

## Phase 1: Go Module and Core Types

### Task 1: Initialize Go Module

**Files:**
- Create: `tmux-agent-status/go.mod`
- Create: `tmux-agent-status/main.go`

**Step 1: Create go.mod**

```bash
cd tmux-agent-status && go mod init github.com/mikeastock/dotagents/tmux-agent-status
```

**Step 2: Create minimal main.go**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: agent-status <command>")
		os.Exit(1)
	}
}
```

**Step 3: Verify it builds**

Run: `cd tmux-agent-status && go build -o agent-status-go .`
Expected: Binary created with no errors

**Step 4: Commit**

```bash
git add tmux-agent-status/go.mod tmux-agent-status/main.go
git commit -m "feat(agent-status): initialize Go module"
```

---

### Task 2: Define Core Types

**Files:**
- Create: `tmux-agent-status/internal/types/types.go`
- Create: `tmux-agent-status/internal/types/types_test.go`

**Step 1: Write test for AgentState validation**

```go
// internal/types/types_test.go
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
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/types/...`
Expected: FAIL (types not defined)

**Step 3: Implement types**

```go
// internal/types/types.go
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
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/types/...`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/types/
git commit -m "feat(agent-status): add core types"
```

---

## Phase 2: JSON-RPC Codec

### Task 3: Define JSON-RPC Message Types

**Files:**
- Create: `tmux-agent-status/internal/jsonrpc/message.go`
- Create: `tmux-agent-status/internal/jsonrpc/message_test.go`

**Step 1: Write test for request/response marshaling**

```go
// internal/jsonrpc/message_test.go
package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestRequestMarshal(t *testing.T) {
	req := Request{
		ID:     1,
		Method: "register",
		Params: json.RawMessage(`{"session":"dev"}`),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Method != "register" {
		t.Errorf("Method = %s, want register", decoded.Method)
	}
}

func TestResponseMarshal(t *testing.T) {
	resp := Response{
		ID:     1,
		Result: json.RawMessage(`{"agent_id":"abc123"}`),
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	if string(data) == "" {
		t.Error("Expected non-empty output")
	}
}

func TestErrorResponse(t *testing.T) {
	resp := Response{
		ID: 1,
		Error: &Error{
			Code:    -32600,
			Message: "Invalid Request",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var decoded Response
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if decoded.Error == nil {
		t.Fatal("Expected error to be set")
	}
	if decoded.Error.Code != -32600 {
		t.Errorf("Error.Code = %d, want -32600", decoded.Error.Code)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/jsonrpc/...`
Expected: FAIL (types not defined)

**Step 3: Implement message types**

```go
// internal/jsonrpc/message.go
package jsonrpc

import "encoding/json"

// Request represents a JSON-RPC request.
type Request struct {
	ID     any             `json:"id,omitempty"` // nil for notifications
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC response.
type Response struct {
	ID     any             `json:"id,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error represents a JSON-RPC error.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrParse          = -32700
	ErrInvalidRequest = -32600
	ErrMethodNotFound = -32601
	ErrInvalidParams  = -32602
	ErrInternal       = -32603
)

// NewError creates an Error with the given code and message.
func NewError(code int, message string) *Error {
	return &Error{Code: code, Message: message}
}

// ErrorParseError returns a parse error.
func ErrorParseError() *Error {
	return NewError(ErrParse, "Parse error")
}

// ErrorInvalidRequest returns an invalid request error.
func ErrorInvalidRequest() *Error {
	return NewError(ErrInvalidRequest, "Invalid Request")
}

// ErrorMethodNotFound returns a method not found error.
func ErrorMethodNotFound() *Error {
	return NewError(ErrMethodNotFound, "Method not found")
}

// ErrorInvalidParams returns an invalid params error.
func ErrorInvalidParams(msg string) *Error {
	return &Error{Code: ErrInvalidParams, Message: msg}
}
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/jsonrpc/...`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/jsonrpc/
git commit -m "feat(agent-status): add JSON-RPC message types"
```

---

### Task 4: Implement NDJSON Codec

**Files:**
- Modify: `tmux-agent-status/internal/jsonrpc/message_test.go`
- Create: `tmux-agent-status/internal/jsonrpc/codec.go`

**Step 1: Write test for NDJSON read/write**

```go
// Add to internal/jsonrpc/message_test.go

func TestCodecReadWrite(t *testing.T) {
	var buf bytes.Buffer
	codec := NewCodec(&buf, &buf)

	// Write a request
	req := Request{
		ID:     1,
		Method: "ping",
	}
	if err := codec.WriteRequest(req); err != nil {
		t.Fatalf("WriteRequest error: %v", err)
	}

	// Buffer should have newline-delimited JSON
	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Error("Expected newline suffix")
	}

	// Read it back
	buf2 := bytes.NewBufferString(line)
	codec2 := NewCodec(buf2, buf2)
	
	gotReq, err := codec2.ReadRequest()
	if err != nil {
		t.Fatalf("ReadRequest error: %v", err)
	}
	if gotReq.Method != "ping" {
		t.Errorf("Method = %s, want ping", gotReq.Method)
	}
}
```

Also add imports at top:
```go
import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/jsonrpc/...`
Expected: FAIL (NewCodec not defined)

**Step 3: Implement codec**

```go
// internal/jsonrpc/codec.go
package jsonrpc

import (
	"bufio"
	"encoding/json"
	"io"
)

// Codec handles NDJSON encoding/decoding for JSON-RPC.
type Codec struct {
	reader *bufio.Reader
	writer io.Writer
}

// NewCodec creates a new NDJSON codec.
func NewCodec(r io.Reader, w io.Writer) *Codec {
	return &Codec{
		reader: bufio.NewReader(r),
		writer: w,
	}
}

// ReadRequest reads a single JSON-RPC request from the stream.
func (c *Codec) ReadRequest() (*Request, error) {
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		return nil, err
	}

	return &req, nil
}

// WriteRequest writes a JSON-RPC request as a single line.
func (c *Codec) WriteRequest(req Request) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.writer.Write(data)
	return err
}

// WriteResponse writes a JSON-RPC response as a single line.
func (c *Codec) WriteResponse(resp Response) error {
	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = c.writer.Write(data)
	return err
}

// ReadResponse reads a single JSON-RPC response from the stream.
func (c *Codec) ReadResponse() (*Response, error) {
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, err
	}

	var resp Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/jsonrpc/...`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/jsonrpc/
git commit -m "feat(agent-status): add NDJSON codec"
```

---

## Phase 3: In-Memory Store

### Task 5: Implement Agent Store

**Files:**
- Create: `tmux-agent-status/internal/store/store.go`
- Create: `tmux-agent-status/internal/store/store_test.go`

**Step 1: Write tests for store operations**

```go
// internal/store/store_test.go
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

	// Sessions should be sorted
	if sessions[0].Name != "dev" {
		t.Errorf("First session = %s, want dev", sessions[0].Name)
	}
	if sessions[1].Name != "staging" {
		t.Errorf("Second session = %s, want staging", sessions[1].Name)
	}

	// Dev should have 2 agents
	if len(sessions[0].Agents) != 2 {
		t.Errorf("Dev agents = %d, want 2", len(sessions[0].Agents))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/store/...`
Expected: FAIL (store not defined)

**Step 3: Implement store**

```go
// internal/store/store.go
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
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/store/...`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/store/
git commit -m "feat(agent-status): add in-memory agent store"
```

---

## Phase 4: Rendering

### Task 6: Implement Tmux Renderer

**Files:**
- Create: `tmux-agent-status/internal/render/render.go`
- Create: `tmux-agent-status/internal/render/render_test.go`

**Step 1: Write tests for tmux rendering**

```go
// internal/render/render_test.go
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
	// Order: waiting > working > idle
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
				{State: types.StateWorking}, // Duplicate
			},
		},
	}
	out := Tmux(sessions)
	want := "dev #[fg=green]●#[fg=default]"
	if out != want {
		t.Errorf("Got %q, want %q", out, want)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/render/...`
Expected: FAIL (Tmux not defined)

**Step 3: Implement renderer**

```go
// internal/render/render.go
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
	// Priority order: waiting > working > idle
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
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/render/...`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/render/
git commit -m "feat(agent-status): add tmux renderer"
```

---

## Phase 5: Daemon Server

### Task 7: Implement RPC Handler

**Files:**
- Create: `tmux-agent-status/internal/server/handler.go`
- Create: `tmux-agent-status/internal/server/handler_test.go`

**Step 1: Write tests for RPC method handling**

```go
// internal/server/handler_test.go
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

	// First register
	agentID := s.Register("conn1", "dev", "%1", types.AgentPi, types.StateIdle)

	params, _ := json.Marshal(map[string]string{
		"state": "working",
	})

	req := &jsonrpc.Request{
		ID:     1,
		Method: "update",
		Params: params,
	}

	// Set the agent ID in handler context
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
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/server/...`
Expected: FAIL (Handler not defined)

**Step 3: Implement handler**

```go
// internal/server/handler.go
package server

import (
	"encoding/json"
	"sync"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

// Handler processes JSON-RPC requests.
type Handler struct {
	store    *store.Store
	mu       sync.RWMutex
	agentIDs map[string]string // connID -> agentID
}

// NewHandler creates a new Handler with the given store.
func NewHandler(s *store.Store) *Handler {
	return &Handler{
		store:    s,
		agentIDs: make(map[string]string),
	}
}

// SetAgentID associates an agent ID with a connection.
func (h *Handler) SetAgentID(connID, agentID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.agentIDs[connID] = agentID
}

// GetAgentID retrieves the agent ID for a connection.
func (h *Handler) GetAgentID(connID string) (string, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	id, ok := h.agentIDs[connID]
	return id, ok
}

// RemoveConnection cleans up a connection's state.
func (h *Handler) RemoveConnection(connID string) {
	h.mu.Lock()
	delete(h.agentIDs, connID)
	h.mu.Unlock()
	h.store.RemoveByConnection(connID)
}

// Handle processes a single JSON-RPC request.
func (h *Handler) Handle(connID string, req *jsonrpc.Request) jsonrpc.Response {
	resp := jsonrpc.Response{ID: req.ID}

	switch req.Method {
	case "ping":
		resp.Result = mustMarshal(map[string]string{"pong": "ok"})

	case "register":
		resp = h.handleRegister(connID, req)

	case "update":
		resp = h.handleUpdate(connID, req)

	case "unregister":
		resp = h.handleUnregister(connID, req)

	case "status":
		resp = h.handleStatus(req)

	default:
		resp.Error = jsonrpc.ErrorMethodNotFound()
	}

	return resp
}

type registerParams struct {
	Session string `json:"session"`
	Pane    string `json:"pane"`
	Agent   string `json:"agent"`
	State   string `json:"state"`
}

func (h *Handler) handleRegister(connID string, req *jsonrpc.Request) jsonrpc.Response {
	resp := jsonrpc.Response{ID: req.ID}

	var params registerParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		resp.Error = jsonrpc.ErrorInvalidParams(err.Error())
		return resp
	}

	if params.Session == "" {
		resp.Error = jsonrpc.ErrorInvalidParams("session is required")
		return resp
	}

	agentType := types.AgentType(params.Agent)
	if agentType != types.AgentPi && agentType != types.AgentCodex {
		agentType = types.AgentPi // default
	}

	state := types.AgentState(params.State)
	if !state.Valid() {
		state = types.StateIdle
	}

	agentID := h.store.Register(connID, params.Session, params.Pane, agentType, state)
	h.SetAgentID(connID, agentID)

	resp.Result = mustMarshal(map[string]string{"agent_id": agentID})
	return resp
}

type updateParams struct {
	State string `json:"state"`
}

func (h *Handler) handleUpdate(connID string, req *jsonrpc.Request) jsonrpc.Response {
	resp := jsonrpc.Response{ID: req.ID}

	agentID, ok := h.GetAgentID(connID)
	if !ok {
		resp.Error = jsonrpc.ErrorInvalidParams("not registered")
		return resp
	}

	var params updateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		resp.Error = jsonrpc.ErrorInvalidParams(err.Error())
		return resp
	}

	state := types.AgentState(params.State)
	if !state.Valid() {
		resp.Error = jsonrpc.ErrorInvalidParams("invalid state")
		return resp
	}

	h.store.Update(agentID, state)
	resp.Result = mustMarshal(map[string]string{"ok": "true"})
	return resp
}

func (h *Handler) handleUnregister(connID string, req *jsonrpc.Request) jsonrpc.Response {
	resp := jsonrpc.Response{ID: req.ID}

	agentID, ok := h.GetAgentID(connID)
	if ok {
		h.store.Unregister(agentID)
		h.mu.Lock()
		delete(h.agentIDs, connID)
		h.mu.Unlock()
	}

	resp.Result = mustMarshal(map[string]string{"ok": "true"})
	return resp
}

func (h *Handler) handleStatus(req *jsonrpc.Request) jsonrpc.Response {
	sessions := h.store.ListBySession()
	return jsonrpc.Response{
		ID:     req.ID,
		Result: mustMarshal(map[string]any{"sessions": sessions}),
	}
}

func mustMarshal(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/server/...`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/server/
git commit -m "feat(agent-status): add RPC handler"
```

---

### Task 8: Implement Socket Server

**Files:**
- Create: `tmux-agent-status/internal/server/server.go`
- Add test: `tmux-agent-status/internal/server/server_test.go`

**Step 1: Write integration test for server**

```go
// internal/server/server_test.go
package server

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
)

func TestServerStartStop(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	srv := NewServer(sockPath, store.New())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.ListenAndServe()
	}()

	// Wait for server to start
	time.Sleep(50 * time.Millisecond)

	// Connect and ping
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}

	codec := jsonrpc.NewCodec(conn, conn)
	err = codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "ping",
	})
	if err != nil {
		t.Fatalf("WriteRequest error: %v", err)
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		t.Fatalf("ReadResponse error: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("Unexpected error: %v", resp.Error)
	}

	conn.Close()
	srv.Shutdown()

	select {
	case err := <-errCh:
		if err != nil && err != net.ErrClosed {
			t.Errorf("Server error: %v", err)
		}
	case <-time.After(time.Second):
		t.Error("Server did not shut down")
	}
}

func TestServerConnectionCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")

	s := store.New()
	srv := NewServer(sockPath, s)
	go srv.ListenAndServe()
	defer srv.Shutdown()

	time.Sleep(50 * time.Millisecond)

	// Connect and register
	conn, _ := net.Dial("unix", sockPath)
	codec := jsonrpc.NewCodec(conn, conn)

	params, _ := json.Marshal(map[string]string{
		"session": "dev",
		"pane":    "%1",
		"agent":   "pi",
	})
	codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "register",
		Params: params,
	})
	codec.ReadResponse()

	// Verify agent exists
	sessions := s.ListBySession()
	if len(sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(sessions))
	}

	// Close connection
	conn.Close()

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	// Verify agent removed
	sessions = s.ListBySession()
	if len(sessions) != 0 {
		t.Errorf("Expected 0 sessions after disconnect, got %d", len(sessions))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd tmux-agent-status && go test ./internal/server/... -run TestServer`
Expected: FAIL (NewServer not defined)

**Step 3: Implement server**

```go
// internal/server/server.go
package server

import (
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
)

// Server is the Unix socket daemon.
type Server struct {
	sockPath string
	handler  *Handler
	listener net.Listener
	connID   atomic.Uint64
	wg       sync.WaitGroup
	done     chan struct{}
}

// NewServer creates a new server.
func NewServer(sockPath string, s *store.Store) *Server {
	return &Server{
		sockPath: sockPath,
		handler:  NewHandler(s),
		done:     make(chan struct{}),
	}
}

// ListenAndServe starts the server and blocks until Shutdown is called.
func (s *Server) ListenAndServe() error {
	// Remove stale socket
	os.Remove(s.sockPath)

	ln, err := net.Listen("unix", s.sockPath)
	if err != nil {
		return err
	}
	s.listener = ln

	// Make socket world-readable/writable
	os.Chmod(s.sockPath, 0666)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
				log.Printf("Accept error: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// Shutdown stops the server gracefully.
func (s *Server) Shutdown() {
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
	os.Remove(s.sockPath)
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	connID := s.connID.Add(1)
	connIDStr := string(rune(connID))
	defer s.handler.RemoveConnection(connIDStr)

	codec := jsonrpc.NewCodec(conn, conn)

	for {
		req, err := codec.ReadRequest()
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			return
		}

		resp := s.handler.Handle(connIDStr, req)

		// Only send response if request had an ID
		if req.ID != nil {
			if err := codec.WriteResponse(resp); err != nil {
				log.Printf("Write error: %v", err)
				return
			}
		}
	}
}
```

**Step 4: Run test to verify it passes**

Run: `cd tmux-agent-status && go test ./internal/server/... -run TestServer`
Expected: PASS

**Step 5: Commit**

```bash
git add tmux-agent-status/internal/server/
git commit -m "feat(agent-status): add socket server"
```

---

## Phase 6: CLI Commands

### Task 9: Implement CLI Framework

**Files:**
- Modify: `tmux-agent-status/main.go`
- Create: `tmux-agent-status/cmd/daemon.go`
- Create: `tmux-agent-status/cmd/status.go`

**Step 1: Implement main.go with subcommands**

```go
// main.go
package main

import (
	"fmt"
	"os"

	"github.com/mikeastock/dotagents/tmux-agent-status/cmd"
)

func main() {
	if len(os.Args) < 2 {
		// Default to status
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
```

**Step 2: Implement daemon command**

```go
// cmd/daemon.go
package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/server"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/store"
)

// DefaultSocketPath returns the default socket path.
func DefaultSocketPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "agents", "agent-status.sock")
}

// RunDaemon starts the daemon server.
func RunDaemon(args []string) error {
	sockPath := DefaultSocketPath()

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(sockPath), 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	s := store.New()
	srv := server.NewServer(sockPath, s)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		srv.Shutdown()
	}()

	fmt.Printf("Listening on %s\n", sockPath)
	return srv.ListenAndServe()
}
```

**Step 3: Implement status command**

```go
// cmd/status.go
package cmd

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/mikeastock/dotagents/tmux-agent-status/internal/jsonrpc"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/render"
	"github.com/mikeastock/dotagents/tmux-agent-status/internal/types"
)

// RunStatus queries the daemon and prints tmux-formatted output.
func RunStatus(args []string) error {
	sockPath := DefaultSocketPath()

	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		// Daemon not running - silent exit for tmux
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second))

	codec := jsonrpc.NewCodec(conn, conn)
	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "status",
	}); err != nil {
		return nil // Silent fail
	}

	resp, err := codec.ReadResponse()
	if err != nil {
		return nil // Silent fail
	}

	if resp.Error != nil {
		return nil // Silent fail
	}

	var result struct {
		Sessions []types.SessionStatus `json:"sessions"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil
	}

	output := render.Tmux(result.Sessions)
	if output != "" {
		fmt.Print(output)
	}

	return nil
}
```

**Step 4: Build and test**

Run: `cd tmux-agent-status && go build -o agent-status-go . && ./agent-status-go help`
Expected: Help output with all commands listed

**Step 5: Commit**

```bash
git add tmux-agent-status/main.go tmux-agent-status/cmd/
git commit -m "feat(agent-status): add CLI framework with daemon and status"
```

---

### Task 10: Implement Notify Command (Codex Bridge)

**Files:**
- Create: `tmux-agent-status/cmd/notify.go`

**Step 1: Write notify command**

```go
// cmd/notify.go
package cmd

import (
	"encoding/json"
	"fmt"
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
		// Read from stdin
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
		return nil // Silently ignore invalid JSON
	}

	// Extract event type
	eventType := extractEventType(notification)

	var state string
	if waitingEvents[eventType] {
		state = "waiting"
	} else if workingEvents[eventType] {
		state = "working"
	} else {
		return nil // Ignore unknown events
	}

	// Get tmux session
	session, pane := getTmuxInfo()
	if session == "" {
		return nil // Not in tmux
	}

	// Connect to daemon
	sockPath := DefaultSocketPath()
	conn, err := net.DialTimeout("unix", sockPath, time.Second)
	if err != nil {
		return nil // Daemon not running
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Second))
	codec := jsonrpc.NewCodec(conn, conn)

	// Register (Codex is one-shot, so we register each time)
	params, _ := json.Marshal(map[string]string{
		"session": session,
		"pane":    pane,
		"agent":   "codex",
		"state":   state,
	})

	codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "register",
		Params: params,
	})

	// Don't wait for response - fire and forget
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
```

**Step 2: Build and verify**

Run: `cd tmux-agent-status && go build -o agent-status-go .`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add tmux-agent-status/cmd/notify.go
git commit -m "feat(agent-status): add notify command for Codex bridge"
```

---

### Task 11: Implement Debug Commands

**Files:**
- Create: `tmux-agent-status/cmd/debug.go`

**Step 1: Implement register, update, unregister, list**

```go
// cmd/debug.go
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
	if len(args) < 1 {
		return fmt.Errorf("usage: update <state>")
	}

	state := args[0]

	conn, err := connectDaemon()
	if err != nil {
		return err
	}
	defer conn.Close()

	codec := jsonrpc.NewCodec(conn, conn)
	params, _ := json.Marshal(map[string]string{
		"state": state,
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

// RunUnregister removes the current agent (for testing).
func RunUnregister(args []string) error {
	conn, err := connectDaemon()
	if err != nil {
		return err
	}
	defer conn.Close()

	codec := jsonrpc.NewCodec(conn, conn)
	if err := codec.WriteRequest(jsonrpc.Request{
		ID:     1,
		Method: "unregister",
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

	// Pretty print
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
```

**Step 2: Build and test**

Run: `cd tmux-agent-status && go build -o agent-status-go .`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add tmux-agent-status/cmd/debug.go
git commit -m "feat(agent-status): add debug commands"
```

---

## Phase 7: Pi Extension Rewrite

### Task 12: Rewrite Pi Extension for Socket

**Files:**
- Modify: `extensions/pi/agent-status/index.ts`

**Step 1: Rewrite extension to use Unix socket**

```typescript
/**
 * Agent Status Extension
 *
 * Connects to the agent-status daemon via Unix socket for tmux status integration.
 * Connection lifecycle = agent liveness (no PID tracking needed).
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { execSync } from "node:child_process";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";

type AgentState = "idle" | "working" | "waiting";

const SOCKET_PATH = path.join(os.homedir(), ".config", "agents", "agent-status.sock");
const WAIT_EVENT = "agent-status:wait";

interface WaitEvent {
	active: boolean;
	source?: string;
}

interface JsonRpcRequest {
	id?: number;
	method: string;
	params?: Record<string, unknown>;
}

interface JsonRpcResponse {
	id?: number;
	result?: unknown;
	error?: { code: number; message: string };
}

function getTmuxInfo(): { session: string; pane: string | null } | null {
	const tmuxPane = process.env.TMUX_PANE;
	if (!tmuxPane) return null;

	try {
		const result = execSync("tmux display-message -p '#S\n#{pane_id}'", {
			encoding: "utf-8",
			timeout: 1000,
		}).trim();
		const lines = result.split("\n");
		const session = lines[0] || null;
		const pane = lines[1] || null;
		if (!session) return null;
		return { session, pane };
	} catch {
		return null;
	}
}

function isWaitEvent(payload: unknown): payload is WaitEvent {
	return (
		typeof payload === "object" &&
		payload !== null &&
		typeof (payload as WaitEvent).active === "boolean"
	);
}

export default function (pi: ExtensionAPI) {
	const tmuxInfo = getTmuxInfo();
	if (!tmuxInfo) return;

	const { session, pane } = tmuxInfo;

	let socket: net.Socket | null = null;
	let requestId = 0;
	let connected = false;

	function sendRequest(method: string, params?: Record<string, unknown>): void {
		if (!socket || !connected) return;

		const req: JsonRpcRequest = {
			method,
			params,
		};

		// Fire-and-forget (no id = notification)
		try {
			socket.write(JSON.stringify(req) + "\n");
		} catch {
			// Ignore write errors
		}
	}

	function sendRequestWithResponse(
		method: string,
		params?: Record<string, unknown>,
	): Promise<JsonRpcResponse> {
		return new Promise((resolve) => {
			if (!socket || !connected) {
				resolve({ error: { code: -1, message: "not connected" } });
				return;
			}

			const id = ++requestId;
			const req: JsonRpcRequest = { id, method, params };

			const handleData = (data: Buffer) => {
				const lines = data.toString().split("\n").filter(Boolean);
				for (const line of lines) {
					try {
						const resp: JsonRpcResponse = JSON.parse(line);
						if (resp.id === id) {
							socket?.off("data", handleData);
							resolve(resp);
							return;
						}
					} catch {
						// Ignore parse errors
					}
				}
			};

			socket.on("data", handleData);

			try {
				socket.write(JSON.stringify(req) + "\n");
			} catch (err) {
				socket.off("data", handleData);
				resolve({ error: { code: -1, message: String(err) } });
			}

			// Timeout
			setTimeout(() => {
				socket?.off("data", handleData);
				resolve({ error: { code: -1, message: "timeout" } });
			}, 5000);
		});
	}

	function updateState(newState: AgentState): void {
		sendRequest("update", { state: newState });
	}

	function connect(): void {
		socket = net.createConnection(SOCKET_PATH);

		socket.on("connect", async () => {
			connected = true;

			// Register with daemon
			await sendRequestWithResponse("register", {
				session,
				pane,
				agent: "pi",
				state: "idle",
			});
		});

		socket.on("error", () => {
			connected = false;
		});

		socket.on("close", () => {
			connected = false;
			// Attempt reconnect after delay
			setTimeout(() => {
				if (!connected) connect();
			}, 5000);
		});
	}

	// Start connection
	connect();

	pi.on("agent_start", async () => {
		updateState("working");
	});

	pi.events.on(WAIT_EVENT, (payload) => {
		if (!isWaitEvent(payload)) return;
		updateState(payload.active ? "waiting" : "working");
	});

	pi.on("agent_end", async () => {
		updateState("waiting");
	});

	pi.on("session_shutdown", async () => {
		if (socket) {
			sendRequest("unregister");
			socket.end();
		}
	});

	const cleanup = () => {
		try {
			if (socket) {
				socket.destroy();
			}
		} catch {
			// Ignore cleanup errors
		}
	};

	process.on("SIGINT", cleanup);
	process.on("SIGTERM", cleanup);
	process.on("exit", cleanup);
}
```

**Step 2: Test type-checking**

Run: `cd /Users/mikeastock/code/personal/dotagents && pnpm exec tsc --noEmit`
Expected: No type errors

**Step 3: Commit**

```bash
git add extensions/pi/agent-status/index.ts
git commit -m "refactor(agent-status): rewrite Pi extension for socket daemon"
```

---

## Phase 8: Build Integration

### Task 13: Update Makefile and Install

**Files:**
- Modify: `Makefile`
- Modify: `tmux-agent-status/README.md`

**Step 1: Add Go build target to Makefile**

Add to Makefile after existing targets:

```makefile
# Go daemon build
AGENT_STATUS_GO := tmux-agent-status/agent-status-go

$(AGENT_STATUS_GO): tmux-agent-status/main.go tmux-agent-status/cmd/*.go tmux-agent-status/internal/**/*.go
	cd tmux-agent-status && go build -o agent-status-go .

build-agent-status: $(AGENT_STATUS_GO)

install-tmux: build-agent-status
	@mkdir -p ~/.local/bin
	@ln -sf $(abspath $(AGENT_STATUS_GO)) ~/.local/bin/agent-status
	@echo "Installed agent-status to ~/.local/bin/"

clean-tmux:
	rm -f $(AGENT_STATUS_GO)
	rm -f ~/.local/bin/agent-status
```

**Step 2: Update README.md**

Update `tmux-agent-status/README.md`:

```markdown
# tmux-agent-status

Display AI coding agent states in your tmux status bar. Supports multiple agents per session.

```
dev ◉●  staging ○
```

- **◉** Yellow = waiting for user input
- **●** Green = working
- **○** Dim = idle

## Architecture

A Go daemon (`agent-status daemon`) listens on `~/.config/agents/agent-status.sock`. Agents connect via Unix socket and send state updates. When a connection closes, the agent is immediately removed—no PID polling needed.

## Supported Agents

| Agent | Integration |
|-------|-------------|
| **Pi** | Extension holds persistent socket connection |
| **Codex** | `notify` subcommand called via `--notify-command` |

## Installation

```bash
# From the dotagents repo
make install-tmux
```

This installs the `agent-status` binary to `~/.local/bin/`.

## Usage

### Start the daemon

```bash
agent-status daemon
```

Or add to your shell startup / launchd / systemd.

### tmux configuration

Add to `~/.tmux.conf`:

```tmux
set -g status-right '#(agent-status)'
set -g status-interval 2
```

### Codex CLI

```bash
codex --notify-command 'agent-status notify'
```

Or in `~/.codex/config.toml`:
```toml
notify_command = "agent-status notify"
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `agent-status daemon` | Start the daemon |
| `agent-status status` | Query and render (default) |
| `agent-status notify <json>` | Handle Codex notification |
| `agent-status list` | List all agents as JSON |
| `agent-status register/update/unregister` | Debug commands |

## Testing

```bash
cd tmux-agent-status
go test ./...
```

## Files

```
tmux-agent-status/
├── main.go                   # CLI entry point
├── cmd/                      # Subcommand implementations
├── internal/
│   ├── types/                # Core types
│   ├── jsonrpc/              # NDJSON codec
│   ├── store/                # In-memory agent registry
│   ├── server/               # Unix socket daemon
│   └── render/               # Tmux output formatting
├── bin/                      # Legacy scripts (deprecated)
└── test-harness.sh           # E2E tests (update for Go)
```
```

**Step 3: Verify build**

Run: `make build-agent-status`
Expected: Binary created at `tmux-agent-status/agent-status-go`

**Step 4: Commit**

```bash
git add Makefile tmux-agent-status/README.md
git commit -m "build(agent-status): add Go build to Makefile"
```

---

### Task 14: Run All Tests

**Files:**
- None (verification only)

**Step 1: Run Go unit tests**

Run: `cd tmux-agent-status && go test ./... -v`
Expected: All tests pass

**Step 2: Build and smoke test**

```bash
cd tmux-agent-status
go build -o agent-status-go .

# Start daemon in background
./agent-status-go daemon &
DAEMON_PID=$!
sleep 0.5

# Test status (should be empty)
OUTPUT=$(./agent-status-go status)
if [[ -z "$OUTPUT" ]]; then echo "✓ Empty status"; else echo "✗ Expected empty"; fi

# Test list
./agent-status-go list

# Test register
./agent-status-go register dev pi %1

# Test status (should show dev)
./agent-status-go status

# Cleanup
kill $DAEMON_PID
```

Expected: All commands work

**Step 3: Commit final cleanup**

```bash
git add -A
git commit -m "test(agent-status): verify Go daemon implementation"
```

---

## Phase 9: Cleanup Legacy Scripts

### Task 15: Remove Legacy Scripts

**Files:**
- Remove: `tmux-agent-status/bin/agent-status` (bash)
- Remove: `tmux-agent-status/bin/codex-notify` (python)
- Remove: `tmux-agent-status/bin/codex-notify-probe`
- Update: `tmux-agent-status/test-harness.sh` to use Go binary

**Step 1: Remove legacy bin/ directory**

```bash
rm -rf tmux-agent-status/bin/
```

**Step 2: Update test harness for Go binary**

The test harness should be updated to test the Go binary instead. This is a significant rewrite - create a new Go-based test or update the shell script to call `agent-status-go` commands.

**Step 3: Commit cleanup**

```bash
git add -A
git commit -m "chore(agent-status): remove legacy bash/python scripts"
```

---

## Summary

| Phase | Tasks | Components |
|-------|-------|------------|
| 1 | 1-2 | Go module, core types |
| 2 | 3-4 | JSON-RPC codec |
| 3 | 5 | In-memory store |
| 4 | 6 | Tmux renderer |
| 5 | 7-8 | RPC handler, socket server |
| 6 | 9-11 | CLI commands |
| 7 | 12 | Pi extension rewrite |
| 8 | 13-14 | Build integration, tests |
| 9 | 15 | Legacy cleanup |

**Total: ~15 tasks, ~4-6 hours for experienced Go developer**

---

## Open Items (from design doc)

1. **Autostart**: Currently requires manual `daemon` start. Could add logic to `status` to spawn daemon if missing.
2. **Service management**: Consider adding launchd plist for macOS.
3. **Socket path override**: Currently hardcoded. Could add `--socket` flag or `AGENT_STATUS_SOCKET` env var.
