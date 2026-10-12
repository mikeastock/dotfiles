import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type Server, type Socket } from "node:net";
import { z } from "zod";

/**
 * The bridge half of the tool proxy: a loopback socket the MCP servers Muse
 * spawns call back into. Muse never talks to bb directly — it calls a tool, the
 * proxy forwards the call here, and the bridge asks the runtime to run it.
 *
 * One bridge process serves every thread, so the listener is a trust boundary
 * between them and the caller states which thread it is. A caller-stated thread
 * is not a claim the listener can take: the credential has to carry it.
 *
 * So the token is not a property of the process. Each thread's MCP server gets
 * a **grant** minted here — its own secret, bound to that thread and to the
 * exact tool names bb declared for it — and a request is answered only where
 * the presented secret, the stated thread, and the named tool all belong to the
 * same grant. A thread that learns another's token still cannot use it: the
 * thread id it must send is the one the token is bound to, and the tools it
 * may name are that thread's. Revoking a grant is what makes a discarded
 * thread's credential stop working, rather than it living as long as the
 * process does.
 */

const bridgeRequestSchema = z
  .object({
    threadId: z.string().min(1),
    token: z.string().min(1),
    kind: z.literal("toolCall"),
    tool: z.string().min(1),
    callId: z.string().min(1),
    arguments: z.record(z.string(), z.unknown()).default({}),
  })
  .loose();

export interface ToolProxyCall {
  threadId: string;
  tool: string;
  callId: string;
  arguments: Record<string, unknown>;
}

export interface ToolProxyResult {
  ok: true;
  content: { type: "text"; text: string }[] | unknown[];
  isError?: boolean;
}

export interface ToolProxyFailure {
  ok: false;
  error: string;
}

interface ToolProxyGrant {
  threadId: string;
  tools: ReadonlySet<string>;
  secret: Buffer;
}

export interface ToolProxyEndpoint {
  port: number;
  /**
   * Mints a credential for one thread and one tool set, replacing whatever that
   * thread held before — a rebuilt session with different tools must not leave
   * the old set reachable.
   */
  issueGrant(threadId: string, tools: readonly string[]): string;
  revokeGrant(threadId: string): void;
  close(): void;
}

const REJECTION = "rejected tool proxy request";

/**
 * Compares against every live grant rather than looking the token up, so the
 * work done is the same whether a token exists or not.
 */
function findGrant(
  grants: ReadonlyMap<string, ToolProxyGrant>,
  presented: string,
): ToolProxyGrant | null {
  const offered = Buffer.from(presented, "utf8");
  let matched: ToolProxyGrant | null = null;
  for (const grant of grants.values()) {
    if (
      grant.secret.length === offered.length &&
      timingSafeEqual(grant.secret, offered)
    ) {
      matched = grant;
    }
  }
  return matched;
}

export async function startToolProxyEndpoint(args: {
  onCall(call: ToolProxyCall): Promise<ToolProxyResult | ToolProxyFailure>;
  onError?(error: unknown): void;
}): Promise<ToolProxyEndpoint> {
  const grants = new Map<string, ToolProxyGrant>();

  const server: Server = createServer((socket: Socket) => {
    socket.setEncoding("utf8");
    let buffer = "";
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline === -1) {
        return;
      }
      const line = buffer.slice(0, newline);
      buffer = "";
      const parsed = bridgeRequestSchema.safeParse(safeJson(line));
      if (!parsed.success) {
        socket.end(`${JSON.stringify({ ok: false, error: REJECTION })}\n`);
        return;
      }
      const grant = findGrant(grants, parsed.data.token);
      /**
       * All three in one gate, answered identically: which of them failed is
       * not something a caller on the wrong side of this boundary gets to
       * learn.
       */
      if (
        grant === null ||
        grant.threadId !== parsed.data.threadId ||
        !grant.tools.has(parsed.data.tool)
      ) {
        socket.end(`${JSON.stringify({ ok: false, error: REJECTION })}\n`);
        return;
      }
      args
        .onCall({
          threadId: grant.threadId,
          tool: parsed.data.tool,
          callId: parsed.data.callId,
          arguments: parsed.data.arguments,
        })
        .then((result) => {
          socket.end(`${JSON.stringify(result)}\n`);
        })
        .catch((error: unknown) => {
          args.onError?.(error);
          socket.end(
            `${JSON.stringify({
              ok: false,
              error: error instanceof Error ? error.message : String(error),
            })}\n`,
          );
        });
    });
    socket.on("error", (error) => {
      args.onError?.(error);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  server.unref();

  const address = server.address();
  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("tool proxy endpoint did not bind a TCP port");
  }

  return {
    port: address.port,

    issueGrant(threadId, tools) {
      const token = randomBytes(32).toString("hex");
      grants.set(threadId, {
        threadId,
        tools: new Set(tools),
        secret: Buffer.from(token, "utf8"),
      });
      return token;
    },

    revokeGrant(threadId) {
      grants.delete(threadId);
    },

    close: () => {
      grants.clear();
      server.close();
    },
  };
}

function safeJson(line: string): unknown {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}
