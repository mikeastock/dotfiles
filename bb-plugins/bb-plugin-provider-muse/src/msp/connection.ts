import { spawn, type ChildProcess } from "node:child_process";
import { createInterface, type Interface } from "node:readline";
import { experimental_recordProviderChildIo } from "@get-bb/plugin-sdk/provider-bridge";
import type { z } from "zod";
import { mspErrorSchema, type MspError } from "./schemas.js";

const STDERR_TAIL_MAX_LINES = 40;
const CLOSE_AFTER_EXIT_GRACE_MS = 1_000;
const KILL_ESCALATION_MS = 4_000;

export interface MspExitInfo {
  code: number | null;
  signal: NodeJS.Signals | null;
  stderrTail: string;
  spawnFailed: boolean;
}

export interface MspRequestResponder {
  result(value: unknown): void;
  error(code: number, message: string): void;
}

interface CreateMspConnectionOptions {
  command: string;
  args: string[];
  cwd: string;
  env: NodeJS.ProcessEnv;
  recordThreadId: string | null;
  onNotification(method: string, params: unknown): void;
  onRequest(
    method: string,
    params: unknown,
    responder: MspRequestResponder,
  ): void;
  onExit(info: MspExitInfo): void;
}

interface MspRequestArgs<TResult> {
  method: string;
  params?: unknown;
  resultSchema: z.ZodType<TResult>;
  timeoutMs?: number;
}

export interface MspConnection {
  request<TResult>(args: MspRequestArgs<TResult>): Promise<TResult>;
  notify(method: string, params?: unknown): void;
  kill(): void;
  readonly exited: boolean;
}

export class MspExitedError extends Error {
  readonly spawnFailed: boolean;

  constructor(message: string, options?: { spawnFailed?: boolean }) {
    super(message);
    this.name = "MspExitedError";
    this.spawnFailed = options?.spawnFailed ?? false;
  }
}

/**
 * A typed MSP error response. The bridge branches on `data.kind` — never on the
 * message text — because MSP declares the kind vocabulary and leaves the
 * message free-form.
 */
export class MspRequestError extends Error {
  readonly code: number;
  readonly kind: string | null;

  constructor(method: string, error: MspError) {
    super(`muse ${method} failed: ${error.message}`);
    this.name = "MspRequestError";
    this.code = error.code;
    this.kind = error.data?.kind ?? null;
  }
}

interface PendingRequest {
  method: string;
  resolve(value: unknown): void;
  reject(error: Error): void;
  timeout: NodeJS.Timeout | null;
}

interface ParsedLine {
  id?: string | number;
  method?: string;
  result?: unknown;
  error?: unknown;
  params?: unknown;
}

function parseLine(line: string): ParsedLine | null {
  const trimmed = line.trim();
  if (trimmed === "") {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  return parsed as ParsedLine;
}

export function createMspConnection(
  options: CreateMspConnectionOptions,
): MspConnection {
  const child: ChildProcess = spawn(options.command, options.args, {
    cwd: options.cwd,
    env: options.env,
    stdio: ["pipe", "pipe", "pipe"],
  });
  experimental_recordProviderChildIo(child, {
    threadId: options.recordThreadId,
  });

  const pending = new Map<number, PendingRequest>();
  const stderrLines: string[] = [];
  let nextRequestId = 1;
  let finalized = false;
  let spawnFailed = false;
  let exitStatus: {
    code: number | null;
    signal: NodeJS.Signals | null;
  } | null = null;
  let closeGraceTimer: NodeJS.Timeout | null = null;
  let stdoutReader: Interface | null = null;

  function writeLine(message: object): void {
    const stdin = child.stdin;
    if (!stdin || stdin.destroyed || !stdin.writable) {
      return;
    }
    stdin.write(`${JSON.stringify(message)}\n`);
  }

  function finalizeExit(status: {
    code: number | null;
    signal: NodeJS.Signals | null;
  }): void {
    if (finalized) {
      return;
    }
    finalized = true;
    if (closeGraceTimer !== null) {
      clearTimeout(closeGraceTimer);
      closeGraceTimer = null;
    }
    stdoutReader?.close();
    child.stdout?.destroy();
    child.stderr?.destroy();
    const stderrTail = stderrLines.join("\n");
    const error = new MspExitedError(
      `muse serve exited (code ${status.code ?? "null"}, signal ${status.signal ?? "null"})${
        stderrTail === "" ? "" : `: ${stderrTail}`
      }`,
      { spawnFailed },
    );
    for (const [, request] of pending) {
      if (request.timeout !== null) {
        clearTimeout(request.timeout);
      }
      request.reject(error);
    }
    pending.clear();
    options.onExit({ ...status, stderrTail, spawnFailed });
  }

  if (child.stdout) {
    stdoutReader = createInterface({ input: child.stdout, terminal: false });
    stdoutReader.on("line", (line) => {
      if (finalized) {
        return;
      }
      const message = parseLine(line);
      if (message === null) {
        return;
      }

      const id = message.id;
      const hasId = typeof id === "string" || typeof id === "number";

      if (hasId && message.method === undefined) {
        const numericId = typeof id === "number" ? id : Number(id);
        const request = pending.get(numericId);
        if (request === undefined) {
          return;
        }
        pending.delete(numericId);
        if (request.timeout !== null) {
          clearTimeout(request.timeout);
        }
        if (message.error !== undefined) {
          const parsed = mspErrorSchema.safeParse(message.error);
          request.reject(
            new MspRequestError(
              request.method,
              parsed.success
                ? parsed.data
                : { code: 0, message: "muse returned an unreadable error" },
            ),
          );
          return;
        }
        request.resolve(message.result);
        return;
      }

      if (typeof message.method !== "string") {
        return;
      }

      if (hasId) {
        let settled = false;
        options.onRequest(message.method, message.params, {
          result(value) {
            if (settled || finalized) return;
            settled = true;
            writeLine({ jsonrpc: "2.0", id, result: value ?? {} });
          },
          error(code, errorMessage) {
            if (settled || finalized) return;
            settled = true;
            writeLine({
              jsonrpc: "2.0",
              id,
              error: { code, message: errorMessage },
            });
          },
        });
        return;
      }

      options.onNotification(message.method, message.params);
    });
  }

  if (child.stderr) {
    const stderrReader = createInterface({
      input: child.stderr,
      terminal: false,
    });
    stderrReader.on("line", (line) => {
      stderrLines.push(line);
      if (stderrLines.length > STDERR_TAIL_MAX_LINES) {
        stderrLines.shift();
      }
    });
  }

  child.on("error", (error) => {
    spawnFailed = true;
    stderrLines.push(error.message);
    finalizeExit({ code: null, signal: null });
  });

  child.on("exit", (code, signal) => {
    exitStatus = { code: code ?? null, signal: signal ?? null };
    closeGraceTimer = setTimeout(() => {
      finalizeExit(exitStatus ?? { code: null, signal: null });
    }, CLOSE_AFTER_EXIT_GRACE_MS);
    closeGraceTimer.unref?.();
  });

  child.on("close", (code, signal) => {
    finalizeExit(exitStatus ?? { code: code ?? null, signal: signal ?? null });
  });

  return {
    get exited() {
      return finalized;
    },

    request({ method, params, resultSchema, timeoutMs }) {
      if (finalized) {
        return Promise.reject(
          new MspExitedError("muse serve is not running", { spawnFailed }),
        );
      }
      const id = nextRequestId;
      nextRequestId += 1;
      return new Promise((resolve, reject) => {
        const entry: PendingRequest = {
          method,
          resolve: (value) => {
            const parsed = resultSchema.safeParse(value);
            if (parsed.success) {
              resolve(parsed.data);
              return;
            }
            reject(
              new Error(
                `muse returned an unexpected ${method} result: ${parsed.error.message}`,
              ),
            );
          },
          reject,
          timeout: null,
        };
        if (timeoutMs !== undefined) {
          entry.timeout = setTimeout(() => {
            pending.delete(id);
            reject(
              new Error(`muse did not answer ${method} within ${timeoutMs}ms`),
            );
          }, timeoutMs);
          entry.timeout.unref?.();
        }
        pending.set(id, entry);
        writeLine({ jsonrpc: "2.0", id, method, params });
      });
    },

    notify(method, params) {
      if (finalized) {
        return;
      }
      writeLine({ jsonrpc: "2.0", method, params });
    },

    kill() {
      if (finalized) {
        return;
      }
      const escalation = setTimeout(() => {
        if (!finalized) {
          child.kill("SIGKILL");
        }
      }, KILL_ESCALATION_MS);
      escalation.unref?.();
      child.kill("SIGTERM");
    },
  };
}
