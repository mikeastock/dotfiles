/**
 * The MCP server Muse spawns to reach bb's injected tools.
 *
 * It ships as source rather than a file in the plugin package because only the
 * built `host.js` artifact reaches a host machine — the bridge writes this into
 * its own persistent dataDir on start and points Muse's config at it.
 *
 * It holds no logic of its own: every call is proxied to the bridge over a
 * loopback socket guarded by a per-process token, and the bridge is what talks
 * to bb.
 */
export const MUSE_TOOL_PROXY_SCRIPT = String.raw`#!/usr/bin/env node
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

const port = Number(process.env.BB_MUSE_TOOL_PORT);
const token = process.env.BB_MUSE_TOOL_TOKEN;
const threadId = process.env.BB_MUSE_TOOL_THREAD_ID;
const toolsJson = process.env.BB_MUSE_TOOLS;

if (!Number.isInteger(port) || port <= 0 || !token || !threadId || !toolsJson) {
  process.stderr.write("bb-bridge MCP: missing proxy environment\n");
  process.exit(1);
}

const tools = JSON.parse(toolsJson);

function write(message) {
  process.stdout.write(JSON.stringify(message) + "\n");
}

function callBridge(payload) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => {
      socket.write(JSON.stringify({ ...payload, threadId, token }) + "\n");
    });
    socket.on("data", (chunk) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline);
      socket.end();
      try {
        resolve(JSON.parse(line));
      } catch (error) {
        reject(error);
      }
    });
    socket.on("error", reject);
    socket.on("end", () => {
      if (!buffer.includes("\n")) {
        reject(new Error("bb bridge closed without a response"));
      }
    });
  });
}

async function handle(message) {
  const { id, method, params } = message;
  if (id === undefined || typeof method !== "string") return;

  if (method === "initialize") {
    write({
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion:
          typeof params?.protocolVersion === "string"
            ? params.protocolVersion
            : "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "bb-bridge", version: "1.0.0" },
      },
    });
    return;
  }

  if (method === "tools/list") {
    write({
      jsonrpc: "2.0",
      id,
      result: {
        tools: tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema ?? { type: "object", properties: {} },
        })),
      },
    });
    return;
  }

  if (method === "tools/call") {
    const name = typeof params?.name === "string" ? params.name : "";
    const tool = tools.find((candidate) => candidate.name === name);
    if (!tool) {
      write({
        jsonrpc: "2.0",
        id,
        error: { code: -32602, message: "Unknown tool: " + name },
      });
      return;
    }
    const args =
      params?.arguments && typeof params.arguments === "object"
        ? params.arguments
        : {};
    try {
      const result = await callBridge({
        kind: "toolCall",
        tool: name,
        arguments: args,
        callId: "muse-mcp-" + name + "-" + Date.now(),
      });
      if (result.ok !== true) {
        write({
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: String(result.error ?? "failed") }],
            isError: true,
          },
        });
        return;
      }
      write({
        jsonrpc: "2.0",
        id,
        result: {
          content: result.content,
          ...(result.isError === true ? { isError: true } : {}),
        },
      });
    } catch (error) {
      write({
        jsonrpc: "2.0",
        id,
        result: {
          content: [
            { type: "text", text: error instanceof Error ? error.message : String(error) },
          ],
          isError: true,
        },
      });
    }
    return;
  }

  write({
    jsonrpc: "2.0",
    id,
    error: { code: -32601, message: "Unsupported MCP method: " + method },
  });
}

createInterface({ input: process.stdin, terminal: false }).on("line", (line) => {
  const trimmed = line.trim();
  if (trimmed === "") return;
  let message;
  try {
    message = JSON.parse(trimmed);
  } catch {
    return;
  }
  void handle(message);
});
`;
