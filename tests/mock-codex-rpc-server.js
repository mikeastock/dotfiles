#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');

const socketPath = process.argv[2];
const readyPath = process.argv[3];
const projectDir = process.env.PROJECT_DIR;

if (!socketPath || !readyPath || !projectDir) {
  console.error('usage: mock-codex-rpc-server SOCKET READY_FILE');
  process.exit(2);
}

fs.rmSync(socketPath, { force: true });

const server = net.createServer(socket => {
  let handshook = false;
  let buffer = Buffer.alloc(0);

  socket.on('data', chunk => {
    buffer = Buffer.concat([buffer, chunk]);

    if (!handshook) {
      const marker = buffer.indexOf('\r\n\r\n');
      if (marker === -1) return;

      const request = buffer.slice(0, marker).toString('utf8');
      buffer = buffer.slice(marker + 4);
      socket.write(handshakeResponse(request));
      handshook = true;
    }

    while (true) {
      const frame = readFrame(buffer);
      if (!frame) return;

      buffer = buffer.slice(frame.bytesRead);
      const message = JSON.parse(frame.payload.toString('utf8'));
      const response = responseFor(message);
      if (response) writeFrame(socket, Buffer.from(JSON.stringify(response)));
    }
  });
});

server.listen(socketPath, () => {
  fs.writeFileSync(readyPath, 'ready\n');
});

function handshakeResponse(request) {
  const match = /^Sec-WebSocket-Key:\s*(.+)$/im.exec(request);
  const key = match ? match[1].trim() : '';
  const accept = crypto
    .createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');

  return [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '',
    '',
  ].join('\r\n');
}

function readFrame(buffer) {
  if (buffer.length < 2) return null;

  const second = buffer[1];
  const masked = Boolean(second & 0x80);
  let length = second & 0x7f;
  let offset = 2;

  if (length === 126) {
    if (buffer.length < offset + 2) return null;
    length = buffer.readUInt16BE(offset);
    offset += 2;
  } else if (length === 127) {
    if (buffer.length < offset + 8) return null;
    length = Number(buffer.readBigUInt64BE(offset));
    offset += 8;
  }

  const maskLength = masked ? 4 : 0;
  if (buffer.length < offset + maskLength + length) return null;

  const mask = masked ? buffer.slice(offset, offset + 4) : null;
  offset += maskLength;
  let payload = buffer.slice(offset, offset + length);
  if (mask) {
    payload = Buffer.from(payload);
    for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
  }

  return {
    bytesRead: offset + length,
    payload,
  };
}

function writeFrame(socket, payload) {
  const length = payload.length;
  let header;

  if (length < 126) {
    header = Buffer.from([0x81, length]);
  } else if (length < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81;
    header[1] = 126;
    header.writeUInt16BE(length, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(length), 2);
  }

  socket.write(Buffer.concat([header, payload]));
}

function responseFor(message) {
  if (!Object.prototype.hasOwnProperty.call(message, 'id')) return null;

  if (message.method === 'initialize') {
    return { jsonrpc: '2.0', id: message.id, result: {} };
  }

  if (message.method !== 'thread/list') {
    return {
      jsonrpc: '2.0',
      id: message.id,
      error: { code: -32601, message: `unexpected method: ${message.method}` },
    };
  }

  if (message.params?.archived) {
    return { jsonrpc: '2.0', id: message.id, result: { data: [], nextCursor: null } };
  }

  return {
    jsonrpc: '2.0',
    id: message.id,
    result: {
      data: [
        {
          id: 'thread-1',
          cwd: `${projectDir}/../app6`,
          path: projectDir,
          name: 'a6(merged): Fix checkout flow',
        },
      ],
      nextCursor: null,
    },
  };
}
