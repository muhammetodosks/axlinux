// Package protocol defines the JSON-RPC message types used between
// axctl/axc and axdaemon over the Unix socket.
package protocol

import "encoding/json"

// Request represents an incoming JSON-RPC style request.
type Request struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
	ID     int             `json:"id"`
}

// Response represents the outgoing JSON-RPC style response.
type Response struct {
	Result json.RawMessage `json:"result"`
	Error  *RPCError       `json:"error"`
	ID     int             `json:"id"`
}

// RPCError is a structured error payload.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewResponse builds a successful response.
func NewResponse(id int, result interface{}) Response {
	raw, err := json.Marshal(result)
	if err != nil {
		return Response{
			Result: json.RawMessage(`null`),
			Error:  &RPCError{Code: -32603, Message: "internal marshal error"},
			ID:     id,
		}
	}
	return Response{Result: raw, Error: nil, ID: id}
}

// NewErrorResponse builds an error response.
func NewErrorResponse(id int, code int, message string) Response {
	return Response{
		Result: json.RawMessage(`null`),
		Error:  &RPCError{Code: code, Message: message},
		ID:     id,
	}
}
