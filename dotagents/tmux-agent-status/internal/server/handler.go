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

	case "upsert":
		resp = h.handleUpsert(req)

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
		agentType = types.AgentPi
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

func (h *Handler) handleUpsert(req *jsonrpc.Request) jsonrpc.Response {
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
		agentType = types.AgentPi
	}

	state := types.AgentState(params.State)
	if !state.Valid() {
		state = types.StateIdle
	}

	agentID := h.store.Upsert(params.Session, params.Pane, agentType, state)
	resp.Result = mustMarshal(map[string]string{"agent_id": agentID})
	return resp
}

type updateParams struct {
	AgentID string `json:"agent_id"`
	State   string `json:"state"`
}

func (h *Handler) handleUpdate(connID string, req *jsonrpc.Request) jsonrpc.Response {
	resp := jsonrpc.Response{ID: req.ID}

	var params updateParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		resp.Error = jsonrpc.ErrorInvalidParams(err.Error())
		return resp
	}

	agentID := params.AgentID
	if agentID == "" {
		var ok bool
		agentID, ok = h.GetAgentID(connID)
		if !ok {
			resp.Error = jsonrpc.ErrorInvalidParams("not registered")
			return resp
		}
	}

	state := types.AgentState(params.State)
	if !state.Valid() {
		resp.Error = jsonrpc.ErrorInvalidParams("invalid state")
		return resp
	}

	if !h.store.Update(agentID, state) {
		resp.Error = jsonrpc.ErrorInvalidParams("not registered")
		return resp
	}
	resp.Result = mustMarshal(map[string]string{"ok": "true"})
	return resp
}

type unregisterParams struct {
	AgentID string `json:"agent_id"`
}

func (h *Handler) handleUnregister(connID string, req *jsonrpc.Request) jsonrpc.Response {
	resp := jsonrpc.Response{ID: req.ID}

	var params unregisterParams
	if len(req.Params) != 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			resp.Error = jsonrpc.ErrorInvalidParams(err.Error())
			return resp
		}
	}

	if params.AgentID != "" {
		if _, ok := h.store.Get(params.AgentID); !ok {
			resp.Error = jsonrpc.ErrorInvalidParams("not registered")
			return resp
		}
		h.store.Unregister(params.AgentID)
		resp.Result = mustMarshal(map[string]string{"ok": "true"})
		return resp
	}

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
