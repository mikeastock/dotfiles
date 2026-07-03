'use strict';

const crypto = require('node:crypto');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

function defaultSocketPath() {
  const codexHome = process.env.CODEX_HOME || path.join(os.homedir(), '.codex');
  return path.join(codexHome, 'app-server-control', 'app-server-control.sock');
}

async function rpc(method, params, options = {}) {
  const client = new UnixWebSocketRpc(options.socketPath || process.env.CODEX_APP_SERVER_SOCKET || defaultSocketPath());
  const timeoutMs = options.timeoutMs || Number(process.env.CODEX_RPC_TIMEOUT_MS || 15000);
  const timer = setTimeout(() => client.close(), timeoutMs);

  try {
    await client.connect();
    await client.request('initialize', {
      clientInfo: { name: options.clientName || 'dotfiles-codex-rpc', version: options.clientVersion || '0.1.0' },
      capabilities: { experimentalApi: true, optOutNotificationMethods: [] },
    });
    client.notify('initialized');
    return await client.request(method, params);
  } finally {
    clearTimeout(timer);
    client.close();
  }
}

function serverResponseForRequest(msg) {
  if (msg.method === 'currentTime/read') {
    return { id: msg.id, result: { currentTimeAt: Math.floor(Date.now() / 1000) } };
  }

  return {
    id: msg.id,
    error: { code: -32601, message: `Unhandled server request: ${msg.method}` },
  };
}

class UnixWebSocketRpc {
  constructor(socketPath) {
    this.socketPath = socketPath;
    this.socket = null;
    this.buffer = Buffer.alloc(0);
    this.pending = new Map();
    this.nextId = 1;
  }

  async connect() {
    this.socket = net.createConnection(this.socketPath);
    await once(this.socket, 'connect');

    const key = crypto.randomBytes(16).toString('base64');
    this.socket.write([
      'GET /rpc HTTP/1.1',
      'Host: localhost',
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${key}`,
      'Sec-WebSocket-Version: 13',
      '',
      '',
    ].join('\r\n'));

    const response = await this.readHttpResponse();
    if (!response.startsWith('HTTP/1.1 101 ') && !response.startsWith('HTTP/1.0 101 ')) {
      throw new Error(`websocket handshake failed: ${response.split('\r\n')[0] || response}`);
    }

    this.socket.on('data', chunk => this.receive(chunk));
    this.socket.on('error', error => this.rejectAll(error));
    this.socket.on('close', () => this.rejectAll(new Error('websocket closed')));
    this.parseFrames();
  }

  request(method, params) {
    const id = this.nextId++;
    const msg = params === undefined
      ? { jsonrpc: '2.0', id, method }
      : { jsonrpc: '2.0', id, method, params };
    this.writeJson(msg);
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }

  notify(method, params) {
    const msg = params === undefined
      ? { jsonrpc: '2.0', method }
      : { jsonrpc: '2.0', method, params };
    this.writeJson(msg);
  }

  writeJson(msg) {
    this.writeFrame(0x1, Buffer.from(JSON.stringify(msg)));
  }

  writeFrame(opcode, payload) {
    const mask = crypto.randomBytes(4);
    const length = payload.length;
    let header;

    if (length < 126) {
      header = Buffer.from([0x80 | opcode, 0x80 | length]);
    } else if (length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 126;
      header.writeUInt16BE(length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | opcode;
      header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(length), 2);
    }

    const masked = Buffer.alloc(length);
    for (let i = 0; i < length; i += 1) masked[i] = payload[i] ^ mask[i % 4];
    this.socket.write(Buffer.concat([header, mask, masked]));
  }

  readHttpResponse() {
    return new Promise((resolve, reject) => {
      const onData = chunk => {
        if (chunk) this.buffer = Buffer.concat([this.buffer, chunk]);
        const marker = this.buffer.indexOf('\r\n\r\n');
        if (marker === -1) return;

        const head = this.buffer.slice(0, marker).toString('utf8');
        this.buffer = this.buffer.slice(marker + 4);
        cleanup();
        resolve(head);
        this.parseFrames();
      };
      const onError = error => {
        cleanup();
        reject(error);
      };
      const cleanup = () => {
        this.socket.off('data', onData);
        this.socket.off('error', onError);
      };

      this.socket.on('data', onData);
      this.socket.on('error', onError);
      onData();
    });
  }

  receive(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    this.parseFrames();
  }

  parseFrames() {
    while (this.buffer.length >= 2) {
      const first = this.buffer[0];
      const second = this.buffer[1];
      const opcode = first & 0x0f;
      const masked = Boolean(second & 0x80);
      let length = second & 0x7f;
      let offset = 2;

      if (length === 126) {
        if (this.buffer.length < offset + 2) return;
        length = this.buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (this.buffer.length < offset + 8) return;
        const big = this.buffer.readBigUInt64BE(offset);
        if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('websocket frame too large');
        length = Number(big);
        offset += 8;
      }

      const maskLength = masked ? 4 : 0;
      if (this.buffer.length < offset + maskLength + length) return;

      const mask = masked ? this.buffer.slice(offset, offset + 4) : null;
      offset += maskLength;
      let payload = this.buffer.slice(offset, offset + length);
      this.buffer = this.buffer.slice(offset + length);

      if (mask) {
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
      }

      if (opcode === 0x8) {
        this.rejectAll(new Error('websocket closed'));
        return;
      }
      if (opcode === 0x9) {
        this.writeFrame(0xA, payload);
        continue;
      }
      if (opcode === 0x1) this.handleJson(payload.toString('utf8'));
    }
  }

  handleJson(text) {
    let msg;
    try {
      msg = JSON.parse(text);
    } catch {
      return;
    }

    if (Object.prototype.hasOwnProperty.call(msg, 'id') && this.pending.has(msg.id)) {
      const { resolve, reject } = this.pending.get(msg.id);
      this.pending.delete(msg.id);
      if (msg.error) reject(new Error(JSON.stringify(msg.error)));
      else resolve(msg.result);
      return;
    }

    if (Object.prototype.hasOwnProperty.call(msg, 'id') && msg.method) {
      this.writeJson(serverResponseForRequest(msg));
    }
  }

  rejectAll(error) {
    for (const { reject } of this.pending.values()) reject(error);
    this.pending.clear();
  }

  close() {
    if (this.socket) this.socket.end();
  }
}

function once(emitter, event) {
  return new Promise((resolve, reject) => {
    const onEvent = (...args) => {
      cleanup();
      resolve(args);
    };
    const onError = error => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      emitter.off(event, onEvent);
      emitter.off('error', onError);
    };

    emitter.once(event, onEvent);
    emitter.once('error', onError);
  });
}

module.exports = {
  defaultSocketPath,
  rpc,
};
