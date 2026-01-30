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
