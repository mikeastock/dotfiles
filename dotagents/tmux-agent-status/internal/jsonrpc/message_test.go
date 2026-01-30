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
