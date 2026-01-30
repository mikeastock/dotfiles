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
