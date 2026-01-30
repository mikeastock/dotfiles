package jsonrpc

import (
	"bytes"
	"encoding/json"
	"strings"
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

func TestCodecReadWrite(t *testing.T) {
	var buf bytes.Buffer
	codec := NewCodec(&buf, &buf)

	req := Request{
		ID:     1,
		Method: "ping",
	}
	if err := codec.WriteRequest(req); err != nil {
		t.Fatalf("WriteRequest error: %v", err)
	}

	line := buf.String()
	if !strings.HasSuffix(line, "\n") {
		t.Error("Expected newline suffix")
	}

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
