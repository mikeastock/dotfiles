import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  BRIDGE_INBOUND_REQUEST_METHODS,
  BRIDGE_JSON_RPC_ERRORS,
  BRIDGE_NOTIFICATION_METHODS,
  BRIDGE_REQUEST_METHODS,
  PROVIDER_BRIDGE_PROTOCOL_VERSION,
  THREAD_DELTA_GRAMMAR_V3,
  THREAD_DELTA_NOTIFICATION_METHOD,
  createBridgeIo,
  decodeBridgeJsonRpcResponse,
  decodeToolCallResponsePayload,
  experimental_buildBridgeToolCallContent as buildBridgeToolCallContent,
  experimental_defineProviderBridge,
  initializeParamsSchema,
  isStandaloneBuiltinCompactCommand,
  modelListParamsSchema,
  providerInstallationRunParamsSchema,
  providerInstallationStatusParamsSchema,
  providerMaintenanceParamsSchema,
  runBridgeRequest,
  sanitizeInheritedChildProcessEnv,
  threadDiscardParamsSchema,
  threadForkParamsSchema,
  threadResumeParamsSchema,
  threadStartParamsSchema,
  threadStopParamsSchema,
  turnStartParamsSchema,
  turnSteerParamsSchema,
  withoutBridgeRuntimeEnv,
  type AvailableModel,
  type BridgeExecutionOptions,
  type DynamicTool,
  type PendingInteractionApprovalDecision,
  type PendingInteractionResolution,
  type PromptInput,
  type ThreadDelta,
} from "@get-bb/plugin-sdk/provider-bridge";
import {
  approvalPayloadFromMsp,
  chooseApprovalChoiceId,
  userInputSettlementFromResolution,
  userQuestionPayloadFromMsp,
} from "./interactions.js";
import {
  getMuseInstallationRun,
  getMuseInstallationStatus,
  getMuseProviderHealth,
  getMuseProviderUsage,
} from "./maintenance.js";
import {
  createMspConnection,
  MspExitedError,
  MspRequestError,
  type MspConnection,
  type MspExitInfo,
} from "./msp/connection.js";
import { ensureMuseDataDirSafe } from "./msp/data-home.js";
import { museExecutable } from "./msp/paths.js";
import {
  MSP_METHODS,
  mspApprovalDecideResultSchema,
  mspApprovalListPendingResultSchema,
  mspApprovalRequestParamsSchema,
  mspCommandAckSchema,
  mspEmptyResultSchema,
  mspInitializeResultSchema,
  mspModelCatalogEntrySchema,
  mspModelListResultSchema,
  mspSessionReadResultSchema,
  mspSessionResumeResultSchema,
  mspSessionStartResultSchema,
  mspTurnInterruptResultSchema,
  mspTurnStartResultSchema,
  mspViewGapParamsSchema,
  mspViewPageResultSchema,
  mspTurnSteerResultSchema,
  mspUserInputRequestParamsSchema,
  type MspApprovalRequestParams,
  type MspModelCatalogEntry,
  type MspUserInputRequestParams,
} from "./msp/schemas.js";
import { uuidV7 } from "./msp/uuid.js";
import {
  createMuseUsageStore,
  MUSE_USAGE_CHANGED_METHOD,
} from "./subscription-usage.js";
import { museProviderErrorInfo } from "./error-info.js";
import { classifyTurnFailure } from "./recovery.js";
import {
  constructionSignature,
  createRuntime,
  noteOutboundDeltas,
  waitForTurnSettlement,
  type HostPosture,
  type InFlightTurn,
  type MuseAttachment,
  type MuseRuntime,
  type SessionConstruction,
} from "./session.js";
import { prepareMuseConfigHome } from "./tool-proxy/config-home.js";
import {
  startToolProxyEndpoint,
  type ToolProxyEndpoint,
} from "./tool-proxy/endpoint.js";
import { MUSE_TOOL_PROXY_SCRIPT } from "./tool-proxy/script.js";
import {
  MUSE_APPROVAL_ALLOW_ALL,
  MUSE_DEFAULT_REASONING_LEVEL,
  MUSE_REASONING_EFFORTS,
  MUSE_SESSION_EXTENSION_KIND,
  museApprovalMode,
  museProviderOptionsSchema,
  type MuseProviderOptions,
} from "./vocabulary.js";

const CLIENT_NAME = "bb";
const CLIENT_VERSION = "1";
const HANDSHAKE_TIMEOUT_MS = 30_000;
const COMMAND_TIMEOUT_MS = 120_000;
const INTERRUPT_SETTLE_TIMEOUT_MS = 8_000;
const ZERO_WORK_SETTLEMENT_GRACE_MS = 1_500;
const SESSION_READ_TIMEOUT_MS = 15_000;
const VIEW_PAGE_TIMEOUT_MS = 20_000;
const VIEW_PAGE_LIMIT = 200;
/** A page is bounded work; a session bb has fallen this far behind on is broken. */
const VIEW_PAGE_MAX_PAGES = 200;
/** Overridable so a suite can drive the watchdog without waiting it out. */
function tunedMs(name: string, fallback: number): number {
  const raw = Number(process.env[name]);
  return Number.isFinite(raw) && raw > 0 ? raw : fallback;
}

const VIEW_WATCHDOG_TICK_MS = tunedMs(
  "BB_MUSE_VIEW_WATCHDOG_TICK_MS",
  30_000,
);
/**
 * How long an open turn may say nothing before bb reads the view back itself.
 * Muse's own model-call retry waits 180s before its first re-attempt and
 * reports it, so this sits above that: a turn that is merely slow announces
 * itself, and one that has gone quiet for longer than any of Muse's own
 * silences is worth a page.
 */
/**
 * A read is a recovery mechanism, and being slow to recover costs far less than
 * reading back a turn that is merely busy. Four minutes was under the length of
 * an ordinary foreground command here, so it fired constantly on healthy work.
 */
const VIEW_STALL_MS = tunedMs("BB_MUSE_VIEW_STALL_MS", 600_000);

/**
 * A blocked approval deserves a much faster check than a stalled view.
 *
 * Paging is the expensive part of a reconcile and has to wait out a long quiet
 * window, because a turn that says nothing is usually just busy. Re-reading the
 * pending approval fold is neither: it is one lease-free read, and the thing it
 * catches — Muse holding the whole session on a question that never reached
 * bb — never resolves on its own. Ten minutes of that is ten minutes of a
 * thread doing nothing for no reason.
 */
const APPROVAL_RECHECK_MS = tunedMs("BB_MUSE_APPROVAL_RECHECK_MS", 90_000);

/**
 * `incomplete` is not one of MSP's turn terminals (`completed | failed |
 * cancelled`). It is what a fold reports for a run that has not reached one,
 * so a page can produce it for a turn that is running perfectly well.
 */
function isUnfinishedFold(params: unknown): boolean {
  const record = params as
    | {
        terminal?: unknown;
        reason?: unknown;
        error?: { message?: unknown };
        item?: { status?: unknown };
      }
    | null;
  return (
    record?.terminal === "incomplete" ||
    record?.reason === "incomplete" ||
    record?.error?.message === "incomplete" ||
    /** The same fold one level down: a tool call that has not returned yet. */
    record?.item?.status === "incomplete"
  );
}

/** The view fold a page may replay; everything else has a live authority. */
const REPLAYABLE_VIEW_METHODS = new Set([
  "turn/started",
  "turn/completed",
  "turn/retryScheduled",
  "turn/unqueued",
  "turn/retracted",
  "item/started",
  "item/updated",
  "item/completed",
  "session/tokenUsage",
  "session/contextUsage",
  "session/todoListChanged",
]);

/**
 * How much of a discarded conversation rides into its replacement. Enough for
 * the agent to know what it was doing; small enough that a thread carrying a
 * megabyte of transcript cannot turn one lost session into a stalled turn.
 */
const HANDOFF_CHAR_BUDGET = 12_000;

/**
 * A Muse session's route belongs to the process that opened it, and Muse cannot
 * replay its own encrypted reasoning across a route change. Codex kills its
 * child on release because it can resume a rollout cleanly; Muse cannot, so a
 * thread's child outlives ordinary release and is reclaimed only when bb is
 * plainly done with the thread.
 */
const ATTACHMENT_IDLE_SHUTDOWN_MS = 30 * 60_000;

type JsonRpcId = string | number;
type OutboundMessage = { jsonrpc: "2.0" } & Record<string, unknown>;

const io = createBridgeIo<OutboundMessage>();

function notify(method: string, params: Record<string, unknown>): void {
  io.send({ jsonrpc: "2.0", method, params });
}

let outboundRequestCounter = 0;
const pendingRuntimeRequests = new Map<
  string,
  { resolve(value: unknown): void; reject(error: Error): void }
>();

function sendRuntimeRequest(
  method: string,
  params: Record<string, unknown>,
): Promise<unknown> {
  outboundRequestCounter += 1;
  const id = `muse-req-${outboundRequestCounter}`;
  return new Promise((resolve, reject) => {
    pendingRuntimeRequests.set(id, { resolve, reject });
    io.send({ jsonrpc: "2.0", id, method, params });
  });
}

const attachments = new Map<string, MuseAttachment>();
const attachmentsBySessionId = new Map<string, MuseAttachment>();
let runtimeSerialCounter = 0;

let bridgeDataDir: string | null = null;
const subscriptionUsage = createMuseUsageStore(() =>
  bridgeDataDir === null ? null : join(bridgeDataDir, "subscription-usage.json"),
);
let toolProxy: ToolProxyEndpoint | null = null;
let toolProxyScriptPath: string | null = null;
let maintenanceConnection: MspConnection | null = null;
let maintenanceConnectionPromise: Promise<MspConnection> | null = null;

/**
 * Drops a callback whose runtime has already been replaced, so a late reply can
 * never mutate the session that took its place.
 */
function liveRuntime(threadId: string, serial: number): MuseRuntime | null {
  const runtime = attachments.get(threadId)?.runtime ?? null;
  if (runtime === null || runtime.serial !== serial || runtime.closing) {
    return null;
  }
  return runtime;
}

/**
 * `thread/identity` precedes every delta for a session, so deltas produced
 * before the identity is known wait for it rather than racing it.
 */
function emitDeltas(
  attachment: MuseAttachment,
  deltas: readonly ThreadDelta[],
): void {
  if (deltas.length === 0) {
    return;
  }
  if (attachment.runtime !== null) {
    noteOutboundDeltas(attachment.runtime, deltas);
  }
  if (!attachment.identityAnnounced) {
    attachment.pendingPreIdentityDeltas.push(...deltas);
    return;
  }
  notify(THREAD_DELTA_NOTIFICATION_METHOD, {
    threadId: attachment.threadId,
    deltas,
  });
}

/**
 * Announced on the first session and again whenever a rebuild replaces it.
 *
 * bb resolves an interactive request back to its thread through the provider
 * thread id it last recorded, so an identity announced once and never renewed
 * strands every approval raised on a replacement session: the request is
 * rejected as unresolvable, and the prompt the user is owed never appears while
 * Muse goes on holding the tool call. `session/replaced` reads as a transcript
 * event, not a re-identification, so the identity is restated here.
 */
function announceIdentity(
  attachment: MuseAttachment,
  providerThreadId: string,
): void {
  const changed = attachment.providerSessionId !== providerThreadId;
  if (attachment.providerSessionId !== null && changed) {
    attachmentsBySessionId.delete(attachment.providerSessionId);
  }
  attachment.providerSessionId = providerThreadId;
  attachmentsBySessionId.set(providerThreadId, attachment);
  if (attachment.identityAnnounced && !changed) {
    return;
  }
  const first = !attachment.identityAnnounced;
  attachment.identityAnnounced = true;
  notify(BRIDGE_NOTIFICATION_METHODS.threadIdentity, {
    threadId: attachment.threadId,
    providerThreadId,
    sessionRestorable: true,
  });
  if (!first) {
    return;
  }
  const buffered = attachment.pendingPreIdentityDeltas;
  attachment.pendingPreIdentityDeltas = [];
  if (buffered.length > 0) {
    notify(THREAD_DELTA_NOTIFICATION_METHOD, {
      threadId: attachment.threadId,
      deltas: buffered,
    });
  }
}

function sessionStateDelta(attachment: MuseAttachment): ThreadDelta {
  const runtime = attachment.runtime;
  return {
    kind: "extension.state",
    extensionKind: MUSE_SESSION_EXTENSION_KIND,
    payload: {
      approvalMode: runtime?.approvalMode ?? null,
      modelId: runtime?.modelId ?? null,
      museHome: runtime?.museHome ?? null,
      serverVersion: runtime?.serverVersion ?? null,
      sessionLogPath: runtime?.sessionLogPath ?? null,
    },
  };
}

function parseProviderOptions(options: unknown): MuseProviderOptions {
  const parsed = museProviderOptionsSchema.safeParse(options ?? {});
  return parsed.success ? parsed.data : {};
}

type PermissionPolicy = {
  permissionMode: string;
  permissionScope?: string;
  approvalReviewer?: string | null;
  permissionEscalation?: string | null;
};

function approvalModeFor(policy: PermissionPolicy): string {
  return museApprovalMode(policy);
}

function fullAccess(policy: PermissionPolicy): boolean {
  return policy.permissionScope === "full" || policy.permissionMode === "full";
}

function postureFrom(
  options: MuseProviderOptions,
  policy: PermissionPolicy,
): HostPosture {
  return {
    disableSandbox: options.sandbox !== "on" || fullAccess(policy),
    sandboxNetwork: options.sandboxNetwork ?? "enabled",
    trustWorkspace: options.trustWorkspace !== false,
  };
}

function serveArgs(posture: HostPosture): string[] {
  const args = ["serve"];
  if (posture.disableSandbox) {
    args.push("--disable-sandbox");
  } else {
    args.push("--sandbox-network", posture.sandboxNetwork);
  }
  if (posture.trustWorkspace) {
    args.push("--trust-workspace");
  }
  return args;
}

export function buildConstruction(args: {
  cwd: string;
  options: BridgeExecutionOptions;
  instructionMode: string;
  dynamicTools: readonly DynamicTool[];
}): SessionConstruction {
  const providerOptions = parseProviderOptions(args.options.providerOptions);
  return {
    cwd: args.cwd,
    posture: postureFrom(providerOptions, args.options),
    approvalMode: approvalModeFor(args.options),
    escalation: args.options.permissionEscalation ?? null,
    model: args.options.model,
    toolNames: args.dynamicTools.map((tool) => tool.name),
    instructionMode: args.instructionMode,
  };
}

export function toolsSignature(tools: readonly DynamicTool[]): string {
  return createHash("sha256")
    .update(JSON.stringify(tools.map((tool) => tool.name).sort()))
    .digest("hex")
    .slice(0, 12);
}

let nextConfigHomeSerial = 0;

function configHomeSerial(): string {
  nextConfigHomeSerial += 1;
  return `${process.pid}-${nextConfigHomeSerial}`;
}

async function ensureToolProxy(): Promise<ToolProxyEndpoint | null> {
  if (bridgeDataDir === null) {
    return null;
  }
  if (toolProxy !== null) {
    return toolProxy;
  }
  const scriptPath = join(bridgeDataDir, "bb-tool-proxy.mjs");
  await mkdir(bridgeDataDir, { recursive: true });
  await writeFile(scriptPath, MUSE_TOOL_PROXY_SCRIPT, { mode: 0o700 });
  toolProxyScriptPath = scriptPath;
  toolProxy = await startToolProxyEndpoint({
    onCall: runInjectedTool,
    onError: (error) => {
      process.stderr.write(
        `muse bridge: tool proxy error: ${
          error instanceof Error ? error.message : String(error)
        }\n`,
      );
    },
  });
  return toolProxy;
}

/**
 * Runs one injected tool for the thread its grant is bound to.
 *
 * The endpoint has already established that the caller holds that thread's
 * credential and named a tool the grant covers. This checks the tool against
 * the attachment's live declaration as well, because the grant is a snapshot
 * taken when the config home was written and the attachment is the authority:
 * a tool bb has since withdrawn must not still run on a credential minted when
 * it had not been.
 */
async function runInjectedTool(call: {
  threadId: string;
  tool: string;
  callId: string;
  arguments: Record<string, unknown>;
}) {
  const attachment = attachments.get(call.threadId);
  if (attachment === undefined || attachment.providerSessionId === null) {
    return {
      ok: false as const,
      error: `bb has no live session for thread ${call.threadId}`,
    };
  }
  if (!attachment.dynamicTools.some((tool) => tool.name === call.tool)) {
    return {
      ok: false as const,
      error: `bb does not offer tool ${call.tool} on thread ${call.threadId}`,
    };
  }
  const result = await sendRuntimeRequest(
    BRIDGE_INBOUND_REQUEST_METHODS.toolCall,
    {
      providerThreadId: attachment.providerSessionId,
      threadId: attachment.threadId,
      turnId: null,
      callId: call.callId,
      tool: call.tool,
      arguments: call.arguments,
      providerNativeIds: true,
    },
  );
  const decoded = decodeToolCallResponsePayload(result);
  return {
    ok: true as const,
    content: buildBridgeToolCallContent(decoded),
    isError: decoded.isError,
  };
}

/**
 * Muse reads its MCP configuration once, at host startup, and disables MCP for
 * the whole runtime if that audit fails. A configuration directory therefore
 * belongs to the child it was written for and is never touched again.
 */
async function buildConfigHome(
  threadId: string,
  tools: readonly DynamicTool[],
): Promise<string | null> {
  if (tools.length === 0) {
    return null;
  }
  const proxy = await ensureToolProxy();
  if (proxy === null || bridgeDataDir === null || toolProxyScriptPath === null) {
    return null;
  }
  return prepareMuseConfigHome({
    root: join(
      bridgeDataDir,
      "threads",
      threadId.replace(/[^A-Za-z0-9_-]/gu, "_"),
      `${toolsSignature(tools)}-${configHomeSerial()}`,
    ),
    mcpServer: {
      command: process.execPath,
      args: [toolProxyScriptPath],
      env: {
        /** bb ships as Electron, whose binary needs this to behave as node. */
        ELECTRON_RUN_AS_NODE: "1",
        BB_MUSE_TOOL_PORT: String(proxy.port),
        BB_MUSE_TOOL_TOKEN: proxy.issueGrant(
          threadId,
          tools.map((tool) => tool.name),
        ),
        BB_MUSE_TOOL_THREAD_ID: threadId,
        BB_MUSE_TOOLS: JSON.stringify(
          tools.map((tool) => ({
            name: tool.name,
            description: tool.description,
            inputSchema: tool.inputSchema,
          })),
        ),
      },
    },
  });
}

function childEnv(
  envVars: Record<string, string> | undefined,
  configHome: string | null,
): NodeJS.ProcessEnv {
  const base = sanitizeInheritedChildProcessEnv({
    env: withoutBridgeRuntimeEnv(process.env),
  });
  return {
    ...base,
    ...(envVars ?? {}),
    ...(configHome === null ? {} : { XDG_CONFIG_HOME: configHome }),
  };
}

function spawnChild(args: {
  posture: HostPosture;
  cwd: string;
  env: NodeJS.ProcessEnv;
  recordThreadId: string | null;
  onNotification(method: string, params: unknown): void;
  onRequest(method: string, params: unknown): void;
  onExit(info: MspExitInfo): void;
}): MspConnection {
  return createMspConnection({
    command: museExecutable(process.env),
    args: serveArgs(args.posture),
    cwd: args.cwd,
    env: args.env,
    recordThreadId: args.recordThreadId,
    onNotification: args.onNotification,
    onRequest: (method, params, responder) => {
      args.onRequest(method, params);
      responder.result({});
    },
    onExit: args.onExit,
  });
}

async function handshake(connection: MspConnection): Promise<{
  museHome: string;
  serverVersion: string;
}> {
  const result = await connection.request({
    method: MSP_METHODS.initialize,
    params: {
      clientInfo: { name: CLIENT_NAME, title: "bb", version: CLIENT_VERSION },
      capabilities: { requestedCapabilities: ["userShell"] },
    },
    resultSchema: mspInitializeResultSchema,
    timeoutMs: HANDSHAKE_TIMEOUT_MS,
  });
  connection.notify("initialized");
  return { museHome: result.museHome, serverVersion: result.serverInfo.version };
}

type ConstructionRequest =
  | { kind: "start" }
  | { kind: "fresh" }
  | { kind: "resume"; providerThreadId: string }
  | { kind: "fork"; sourceProviderThreadId: string };

/**
 * Builds the live runtime for an attachment: one `muse serve` child per thread,
 * as codex runs one app-server per session, so no thread can disturb another's
 * configuration, sandbox posture, or session state.
 */
async function constructRuntime(args: {
  attachment: MuseAttachment;
  options: BridgeExecutionOptions;
  request: ConstructionRequest;
}): Promise<MuseRuntime> {
  const { attachment } = args;
  releaseRuntime(attachment, { kill: true });

  const construction = attachment.construction;
  const configHome = await buildConfigHome(
    attachment.threadId,
    attachment.dynamicTools,
  );
  attachment.configHome = configHome;
  const env = childEnv(args.options.envVars, configHome);
  await ensureMuseDataDirSafe(env);

  runtimeSerialCounter += 1;
  const serial = runtimeSerialCounter;
  const connection = spawnChild({
    posture: construction.posture,
    cwd: construction.cwd,
    env,
    recordThreadId: attachment.threadId,
    onNotification: (method, params) =>
      handleChildNotification(attachment.threadId, serial, method, params),
    onRequest: (method, params) =>
      handleChildRequest(attachment.threadId, serial, method, params),
    onExit: (info) => handleChildExit(attachment.threadId, serial, info),
  });

  const runtime = createRuntime({
    serial,
    connection,
    cwd: construction.cwd,
    approvalMode: construction.approvalMode,
  });
  attachment.runtime = runtime;

  try {
    const info = await handshake(connection);
    runtime.museHome = info.museHome;
    runtime.serverVersion = info.serverVersion;

    const session = await openSession({
      connection,
      construction,
      request: args.request,
    });
    runtime.sessionId = session.sessionId;
    runtime.modelId = session.modelId;
    runtime.approvalMode = session.approvalMode ?? construction.approvalMode;
    runtime.sessionLogPath = session.path === "" ? null : session.path;
    runtime.lastViewCursor = session.viewCursor === "" ? null : session.viewCursor;
    runtime.lastViewActivityAt = Date.now();
    startViewWatchdog(attachment, runtime);

    announceIdentity(attachment, session.sessionId);
    emitDeltas(attachment, [
      { kind: "session.reset" },
      sessionStateDelta(attachment),
    ]);
    if (session.replacedUnviewable !== null) {
      await onUnviewableSessionReplaced(
        attachment,
        connection,
        session.replacedUnviewable,
        session.sessionId,
      );
    } else if (args.request.kind === "resume") {
      void reopenPendingInteractions(attachment, runtime);
    }
    return runtime;
  } catch (error) {
    runtime.closing = true;
    stopViewWatchdog(runtime);
    if (attachment.runtime === runtime) {
      attachment.runtime = null;
    }
    connection.kill();
    throw error;
  }
}

/**
 * Reports the one rebuild the caller never asked for: a session bb declined to
 * resume because Muse could not serve its view. It is a context loss like any
 * other fresh start, so it is owed the same things — bb's session instructions,
 * which rode the first turn of the session just abandoned, and a transcript of
 * what that session had already said.
 */
async function onUnviewableSessionReplaced(
  attachment: MuseAttachment,
  connection: MspConnection,
  abandoned: { sessionId: string; reason: string },
  replacementSessionId: string,
): Promise<void> {
  const reason = abandoned.reason;
  attachment.pendingInstructions = attachment.instructions;
  attachment.pendingHandoff = await readSessionHandoff(
    connection,
    abandoned.sessionId,
  );
  notify(BRIDGE_NOTIFICATION_METHODS.sessionReplaced, {
    threadId: attachment.threadId,
    providerThreadId: replacementSessionId,
    reason,
    contextLost: true,
  });
  emitDeltas(attachment, [
    {
      kind: "provider.warning",
      summary: "Muse started a fresh session for this thread",
      details:
        `${reason}. Durable bb state is untouched, and ` +
        (attachment.pendingHandoff === null
          ? "the in-session conversation could not be read back."
          : "the conversation so far is carried into the new session as a transcript."),
    },
  ]);
}

/**
 * Opens a fresh session to stand in for one bb could not keep, and reports the
 * source it replaced so the caller can owe it the handoff every context loss is
 * owed. `unsubscribe` drops a source `session/resume` had already subscribed
 * this connection to: left attached, it goes on pushing cursors from a space
 * the replacement cannot be paged from.
 */
async function startReplacementSession(
  connection: MspConnection,
  construction: SessionConstruction,
  replaced: { sessionId: string; reason: string; unsubscribe?: boolean },
): Promise<{
  sessionId: string;
  modelId: string | null;
  approvalMode: string | null;
  path: string;
  viewCursor: string;
  replacedUnviewable: { sessionId: string; reason: string } | null;
}> {
  const replacement = await connection.request({
    method: MSP_METHODS.sessionStart,
    params: {
      commandId: uuidV7(),
      workspaceRoot: construction.cwd,
      approvalMode: construction.approvalMode,
      ...(construction.model === undefined
        ? {}
        : { modelId: construction.model }),
    },
    resultSchema: mspSessionStartResultSchema,
    timeoutMs: COMMAND_TIMEOUT_MS,
  });
  if (replaced.unsubscribe === true) {
    try {
      await connection.request({
        method: MSP_METHODS.viewUnsubscribe,
        params: { sessionId: replaced.sessionId },
        resultSchema: mspEmptyResultSchema,
        timeoutMs: COMMAND_TIMEOUT_MS,
      });
    } catch {
      /** The session guard on every cursor is what actually has to hold. */
    }
  }
  return {
    sessionId: replacement.session.sessionId,
    modelId: replacement.session.modelId,
    approvalMode: replacement.session.approvalMode?.mode ?? null,
    path: replacement.session.path,
    viewCursor: replacement.viewCursor,
    replacedUnviewable: {
      sessionId: replaced.sessionId,
      reason: replaced.reason,
    },
  };
}

async function openSession(args: {
  connection: MspConnection;
  construction: SessionConstruction;
  request: ConstructionRequest;
}): Promise<{
  sessionId: string;
  modelId: string | null;
  approvalMode: string | null;
  path: string;
  /** Where this connection's view starts; "" where Muse offers no head. */
  viewCursor: string;
  /**
   * Set when a resume was abandoned here for a fresh session — because Muse
   * refused it, or accepted it but could serve no view of it.
   */
  replacedUnviewable: { sessionId: string; reason: string } | null;
}> {
  const { connection, construction, request } = args;

  if (request.kind === "start" || request.kind === "fresh") {
    const result = await connection.request({
      method: MSP_METHODS.sessionStart,
      params: {
        commandId: uuidV7(),
        workspaceRoot: construction.cwd,
        approvalMode: construction.approvalMode,
        ...(construction.model === undefined
          ? {}
          : { modelId: construction.model }),
      },
      resultSchema: mspSessionStartResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    return {
      sessionId: result.session.sessionId,
      modelId: result.session.modelId,
      approvalMode: result.session.approvalMode?.mode ?? null,
      path: result.session.path,
      viewCursor: result.viewCursor,
      replacedUnviewable: null,
    };
  }

  const sourceId =
    request.kind === "resume"
      ? request.providerThreadId
      : request.sourceProviderThreadId;
  let result;
  try {
    result = await connection.request({
      method:
        request.kind === "resume"
          ? MSP_METHODS.sessionResume
          : MSP_METHODS.sessionFork,
      params: { commandId: uuidV7(), sessionId: sourceId, excludeItems: true },
      resultSchema: mspSessionResumeResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
  } catch (error) {
    /**
     * A resume Muse refuses outright. Seen as a session whose durable log Muse
     * will no longer replay — "durable child logical sequence is duplicate or
     * non-monotonic" — which no retry clears, because the defect is on disk.
     *
     * Propagating it rejects the user's prompt and leaves the thread unusable
     * for good: every later message resumes the same broken session and is
     * refused the same way. A fork is the user asking for that specific
     * session and is left to fail, but a resume is bb's own bookkeeping, so it
     * falls back to a fresh session with the conversation carried across.
     */
    if (request.kind !== "resume" || error instanceof MspExitedError) {
      throw error;
    }
    return startReplacementSession(connection, construction, {
      sessionId: sourceId,
      reason:
        error instanceof MspRequestError
          ? `Muse could not reopen this session: ${error.message}`
          : "Muse could not reopen this session",
    });
  }
  /**
   * A resume Muse accepts but hands no view cursor for is a session whose
   * materialized projection it can no longer stand behind. It still runs — and
   * that is the trap: turns execute while no `turn/started` or `turn/completed`
   * ever reaches bb, so the thread either hangs or, worse, settles on nothing.
   * bb will not carry a thread on a session it cannot watch, so the resume is
   * abandoned here for a fresh one and the conversation rides across as a
   * transcript, the same as any other rebuild.
   */
  if (request.kind === "resume" && result.viewCursor === "") {
    return startReplacementSession(connection, construction, {
      sessionId: sourceId,
      reason:
        "Muse could no longer serve a view of this session, so bb started a fresh one",
      unsubscribe: true,
    });
  }

  return {
    sessionId: result.session.sessionId,
    modelId: result.session.modelId,
    approvalMode: result.session.approvalMode?.mode ?? null,
    path: result.session.path,
    viewCursor: result.viewCursor,
    replacedUnviewable: null,
  };
}

function releaseRuntime(
  attachment: MuseAttachment,
  options: { kill: boolean },
): void {
  const runtime = attachment.runtime;
  if (runtime === null) {
    return;
  }
  runtime.closing = true;
  stopViewWatchdog(runtime);
  attachment.runtime = null;
  if (options.kill) {
    runtime.connection.kill();
  }
}

function forgetAttachment(attachment: MuseAttachment): void {
  attachment.closing = true;
  /** The thread is gone, so its tool credential stops working now, not at exit. */
  toolProxy?.revokeGrant(attachment.threadId);
  cancelIdleShutdown(attachment);
  releaseRuntime(attachment, { kill: true });
  attachments.delete(attachment.threadId);
  if (attachment.providerSessionId !== null) {
    attachmentsBySessionId.delete(attachment.providerSessionId);
  }
}

function cancelIdleShutdown(attachment: MuseAttachment): void {
  if (attachment.idleTimer !== null) {
    clearTimeout(attachment.idleTimer);
    attachment.idleTimer = null;
  }
}

function scheduleIdleShutdown(attachment: MuseAttachment): void {
  cancelIdleShutdown(attachment);
  attachment.idleTimer = setTimeout(() => {
    attachment.idleTimer = null;
    releaseRuntime(attachment, { kill: true });
  }, ATTACHMENT_IDLE_SHUTDOWN_MS);
  attachment.idleTimer.unref?.();
}

function attachmentForParams(params: unknown): MuseAttachment | null {
  if (typeof params !== "object" || params === null) {
    return null;
  }
  const sessionId = (params as { sessionId?: unknown }).sessionId;
  return typeof sessionId === "string"
    ? (attachmentsBySessionId.get(sessionId) ?? null)
    : null;
}

/**
 * Records how far the view has been read and when the child last spoke. Every
 * view notification carries its own cursor and they ascend, so the highest one
 * seen is the whole of the resume state a page needs.
 */
function sourceSequenceOf(params: unknown): number | null {
  const range = (params as { sourceRange?: unknown } | null)?.sourceRange as
    | { last?: { sequence?: unknown } }
    | undefined;
  const sequence = range?.last?.sequence;
  return typeof sequence === "number" ? sequence : null;
}

function noteViewActivity(runtime: MuseRuntime, params: unknown): void {
  runtime.lastViewActivityAt = Date.now();
  const record = params as
    | { viewCursor?: unknown; sessionId?: unknown }
    | null;
  /**
   * A view cursor belongs to one session's cursor space and means nothing in
   * another's. A connection can be subscribed to more than one — resuming a
   * session subscribes to it, so a session abandoned during construction goes
   * on pushing here — and paging session B from a cursor minted by session A is
   * refused as an unknown anchor. Which, before this check, is how a healthy
   * turn got settled as a failure.
   */
  if (record?.sessionId !== runtime.sessionId) {
    return;
  }
  const cursor = record.viewCursor;
  if (typeof cursor === "string" && cursor !== "") {
    runtime.lastViewCursor = cursor;
  }
  const sequence = sourceSequenceOf(params);
  if (sequence !== null && sequence > runtime.deliveredThroughSequence) {
    runtime.deliveredThroughSequence = sequence;
  }
}

/**
 * Feeds one page of unframed view notifications back through the translator,
 * in order, as though push had delivered them. Returns the cursor reached.
 */
function replayViewEvents(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  events: readonly { method: string; params: unknown }[],
  stopBefore: string | null,
): { cursor: string | null; stopped: boolean } {
  let cursor: string | null = null;
  for (const event of events) {
    const eventCursor = (event.params as { viewCursor?: unknown } | null)
      ?.viewCursor;
    if (
      stopBefore !== null &&
      typeof eventCursor === "string" &&
      eventCursor === stopBefore
    ) {
      return { cursor, stopped: true };
    }
    if (attachmentForParams(event.params) !== attachment) {
      continue;
    }
    /**
     * Never fold the same source record twice. A re-read from the start of the
     * view is otherwise the whole session again: every command, every result,
     * duplicated on the timeline underneath the live turn.
     */
    const sequence = sourceSequenceOf(event.params);
    if (sequence !== null && sequence <= runtime.deliveredThroughSequence) {
      if (typeof eventCursor === "string" && eventCursor !== "") {
        cursor = eventCursor;
        runtime.lastViewCursor = eventCursor;
      }
      continue;
    }
    /**
     * A page folds a view for work that may still be going, and reports what
     * has not finished as `incomplete`. That is not a terminal — it is the fold
     * saying "not done" — and treating it as one ends work that is still
     * running. At turn level it killed three long commands here, including a
     * four-minute foreground GPU job that was fine. At item level it closed a
     * 24GB `Get-FileHash` as failed, with no exit code and no output, while the
     * process was measurably still running. Only push, a dead child, or the
     * abandon path may end either.
     */
    if (
      (event.method === "turn/completed" ||
        event.method === "item/completed") &&
      isUnfinishedFold(event.params)
    ) {
      if (typeof eventCursor === "string" && eventCursor !== "") {
        cursor = eventCursor;
        runtime.lastViewCursor = eventCursor;
      }
      continue;
    }
    /**
     * Only the view fold is replayed. An approval or a user-input prompt is
     * protected delivery whose live state belongs to the pending fold, and
     * re-opening one Muse has already resolved would put a settled question
     * back in front of the user; `reopenPendingInteractions` reads that fold
     * from the authority instead. A replayed `view/gap` would recurse.
     */
    if (!REPLAYABLE_VIEW_METHODS.has(event.method)) {
      if (typeof eventCursor === "string" && eventCursor !== "") {
        cursor = eventCursor;
        runtime.lastViewCursor = eventCursor;
      }
      continue;
    }
    foldViewNotification(attachment, runtime, event.method, event.params);
    if (typeof eventCursor === "string" && eventCursor !== "") {
      cursor = eventCursor;
      runtime.lastViewCursor = eventCursor;
    }
  }
  return { cursor, stopped: false };
}

/**
 * Reads the session view forward from where this runtime left off, replaying
 * whatever push never delivered.
 *
 * This is the only thing standing between a thread and a permanent "working…".
 * Muse's live view can stop while the session keeps running — its materialized
 * projection is marked unavailable and no further notification arrives, so the
 * turn's own `turn/completed` never reaches bb and the thread reads as busy
 * long after Muse has finished. `view/page` serves from the source log rather
 * than that projection, so it still answers, and replaying it settles the turn.
 */
async function reconcileView(args: {
  attachment: MuseAttachment;
  runtime: MuseRuntime;
  /** The first cursor push already delivered, for a bracketed `view/gap`. */
  stopBefore?: string | null;
  from?: string | null;
}): Promise<void> {
  const { attachment, runtime } = args;
  if (runtime.reconciling || runtime.closing || runtime.connection.exited) {
    return;
  }
  const sessionId = runtime.sessionId;
  if (sessionId === null) {
    return;
  }
  runtime.reconciling = true;
  let cursor = args.from ?? runtime.lastViewCursor ?? "";
  let recovered = 0;
  try {
    for (let page = 0; page < VIEW_PAGE_MAX_PAGES; page += 1) {
      if (liveRuntime(attachment.threadId, runtime.serial) !== runtime) {
        return;
      }
      const result = await runtime.connection.request({
        method: MSP_METHODS.viewPage,
        params: {
          sessionId,
          cursor,
          direction: "forward",
          limit: VIEW_PAGE_LIMIT,
        },
        resultSchema: mspViewPageResultSchema,
        timeoutMs: VIEW_PAGE_TIMEOUT_MS,
      });
      if (liveRuntime(attachment.threadId, runtime.serial) !== runtime) {
        return;
      }
      if (result.events.length === 0) {
        break;
      }
      recovered += result.events.length;
      const replayed = replayViewEvents(
        attachment,
        runtime,
        result.events as { method: string; params: unknown }[],
        args.stopBefore ?? null,
      );
      if (replayed.stopped) {
        break;
      }
      const next = replayed.cursor ?? result.nextCursor ?? null;
      if (next === null || next === cursor) {
        break;
      }
      cursor = next;
    }
    if (recovered > 0) {
      runtime.lastViewActivityAt = Date.now();
      runtime.quietReconciles = 0;
      reportViewGapOnce(attachment, runtime);
    } else if (runtime.openTurnIds.size > 0) {
      runtime.quietReconciles += 1;
      abandonIfSessionStopped(attachment, runtime);
    }
    /**
     * An approval is protected delivery, not a view event, so a page cannot
     * replay one and this read has not recovered it. But a dropped stream drops
     * approvals too, and Muse blocks the whole session on one it is waiting for
     * — indefinitely, because the request that would have reached the user is
     * simply gone. Observed as a contributor that went quiet for fifteen minutes
     * holding `approval_wait.effect.started` while bb showed nothing pending.
     *
     * `approval/listPending` is the authority and a lease-free read, so the fold
     * is re-read whenever the stream has proven lossy. Re-opening is idempotent:
     * anything already pending or in flight is skipped.
     */
    await reopenPendingInteractions(attachment, runtime);
  } catch (error) {
    /**
     * One retry from the beginning of the view before anything is concluded.
     * A rejected anchor says nothing about the session — only that bb asked
     * from the wrong place — and the whole view is always a valid ask.
     */
    if (args.from === undefined && cursor !== "") {
      try {
        runtime.lastViewCursor = null;
        runtime.reconciling = false;
        await reconcileView({ attachment, runtime, from: "" });
        return;
      } catch {
        /** Falls through to the report below. */
      }
    }
    onReconcileFailed(attachment, runtime, error);
  } finally {
    runtime.reconciling = false;
  }
}

function reportViewGapOnce(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
): void {
  if (runtime.reportedViewGap) {
    return;
  }
  runtime.reportedViewGap = true;
  emitDeltas(attachment, [
    {
      kind: "provider.warning",
      summary: "Muse stopped streaming this session; bb read it back",
      details:
        "Muse's live view stream dropped events for this session. bb read the missing range back from the session itself, so the transcript is complete — the streamed text of anything in that range arrives as one block rather than as it was typed.",
    },
  ]);
}

/**
 * Muse declares exactly one condition as unrecoverable by paging, and only that
 * one may end a turn bb cannot see.
 *
 * Everything else a failed page can mean — a rejected anchor, a timeout, a
 * transport hiccup — is bb failing to read, not Muse failing to run. A turn is
 * the user's work in flight, and killing it on a read error trades a thread
 * that looks stuck for one that reports a failure over work still running.
 * That is the worse trade, and it is the one this made before the check.
 */
const VIEW_FATAL_KINDS = new Set(["projectionUnavailable"]);

/**
 * How many reads in a row may come back empty, with a turn open and push
 * silent, before bb calls the session stopped rather than slow.
 *
 * The evidence is what makes this safe to act on. A slow turn is not quiet: a
 * model call still reports its usage, its retries, and its tool rows, and any
 * of that resets the count. Only a session that has produced nothing at all —
 * not on the wire, not in its own view when asked directly — runs the count up,
 * and Muse's longest observed single model call is under three minutes against
 * the ten-plus this takes.
 */
function viewAbandonReads(): number {
  return Math.max(1, Math.round(tunedMs("BB_MUSE_VIEW_ABANDON_READS", 20)));
}

/**
 * The bounded end of a turn nothing will ever finish. Left open it is the
 * original bug — a thread that reads as working forever — and settled early it
 * is the one after that, a failure reported over live work. This settles only
 * on the evidence that neither is true: repeated direct reads of the session's
 * own view, all empty.
 */
function abandonIfSessionStopped(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
): void {
  if (runtime.quietReconciles < viewAbandonReads()) {
    return;
  }
  if (runtime.closing || runtime.openTurnIds.size === 0) {
    return;
  }
  const message =
    "Muse stopped reporting this turn and its own view of the session has " +
    "nothing further in it. bb waited, read the session back repeatedly, and " +
    "found no more work and no terminal, so the turn is settled here rather " +
    "than left running forever. Your next message rebuilds the session.";
  emitDeltas(attachment, [
    {
      kind: "provider.error",
      message,
      settlesTurn: false,
      threadScoped: true,
      category: "internal",
      errorInfo: {
        category: "internal",
        providerCode: "sessionStopped",
        httpStatusCode: null,
      },
    },
  ]);
  emitDeltas(attachment, runtime.translator.settleOpenTurns("failed", message));
  runtime.quietReconciles = 0;
  attachment.restartBeforeNextTurn = {
    reason: "Muse stopped reporting this session",
    fresh: false,
  };
}

function onReconcileFailed(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  error: unknown,
): void {
  if (runtime.closing || runtime.connection.exited) {
    return;
  }
  if (runtime.openTurnIds.size === 0) {
    return;
  }
  const detail = error instanceof Error ? error.message : String(error);
  const fatal =
    error instanceof MspRequestError && VIEW_FATAL_KINDS.has(error.kind ?? "");

  if (!fatal) {
    /** Said once per runtime: a read bb could not make is not news each time. */
    if (!runtime.reportedViewReadFailure) {
      runtime.reportedViewReadFailure = true;
      emitDeltas(attachment, [
        {
          kind: "provider.warning",
          summary: "bb could not read Muse's view of this session",
          details:
            `${detail}. The turn is still Muse's to finish — bb has left it ` +
            "running and will keep trying to read it back. Stop the thread if " +
            "it never reports.",
        },
      ]);
    }
    return;
  }

  const message = `Muse can no longer serve a view of this session: ${detail}`;
  emitDeltas(attachment, [
    {
      kind: "provider.error",
      message,
      settlesTurn: false,
      threadScoped: true,
      category: "internal",
      errorInfo: {
        category: "internal",
        providerCode: "viewUnreadable",
        httpStatusCode: null,
      },
    },
  ]);
  emitDeltas(attachment, runtime.translator.settleOpenTurns("failed", message));
  attachment.restartBeforeNextTurn = {
    reason: "Muse's view of this session could no longer be read",
    fresh: false,
  };
}

async function replayViewGap(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  params: unknown,
): Promise<void> {
  const parsed = mspViewGapParamsSchema.safeParse(params);
  if (!parsed.success) {
    return;
  }
  await reconcileView({
    attachment,
    runtime,
    from: parsed.data.after,
    stopBefore: parsed.data.next,
  });
}

/**
 * The watchdog. A turn that is genuinely working is noisy — Muse reports every
 * tool call, every usage update, every scheduled retry — so a turn that has
 * been open and silent for minutes is either a very long model call or a view
 * that has stopped. Paging tells the two apart, cheaply and without guessing:
 * a working turn's page is empty, and a stalled one's page carries everything
 * bb missed, up to and including the terminal.
 */
function startViewWatchdog(attachment: MuseAttachment, runtime: MuseRuntime): void {
  stopViewWatchdog(runtime);
  const timer = setInterval(() => {
    if (liveRuntime(attachment.threadId, runtime.serial) !== runtime) {
      stopViewWatchdog(runtime);
      return;
    }
    if (runtime.openTurnIds.size === 0 || runtime.reconciling) {
      return;
    }
    const quietFor = Date.now() - runtime.lastViewActivityAt;
    /** Never later than the paging window, however the two are configured. */
    const recheckAt = Math.min(APPROVAL_RECHECK_MS, VIEW_STALL_MS);
    if (quietFor < recheckAt) {
      return;
    }
    /**
     * The cheap check first, and on its own until the view itself looks stalled:
     * an approval bb never received blocks the session outright, and waiting out
     * the paging window to notice costs the whole thread that time.
     */
    if (quietFor < VIEW_STALL_MS) {
      void reopenPendingInteractions(attachment, runtime);
      return;
    }
    void reconcileView({ attachment, runtime });
  }, VIEW_WATCHDOG_TICK_MS);
  timer.unref?.();
  runtime.reconcileTimer = timer;
}

function stopViewWatchdog(runtime: MuseRuntime): void {
  if (runtime.reconcileTimer !== null) {
    clearInterval(runtime.reconcileTimer);
    runtime.reconcileTimer = null;
  }
}

function handleChildNotification(
  threadId: string,
  serial: number,
  method: string,
  params: unknown,
): void {
  /**
   * The plan's meters belong to the account, not to a session: the reading
   * carries no session id, and one from a host that is shutting down is as true
   * as one from a live turn.
   */
  if (method === MUSE_USAGE_CHANGED_METHOD) {
    subscriptionUsage.record(params);
    return;
  }
  const runtime = liveRuntime(threadId, serial);
  const attachment = attachments.get(threadId);
  if (runtime === null || attachment === undefined) {
    return;
  }
  if (attachmentForParams(params) !== attachment) {
    return;
  }
  noteViewActivity(runtime, params);

  switch (method) {
    /**
     * Push delivery dropped events and told us the range. Everything in it is
     * still in the view, so it is read back rather than mourned in a warning:
     * an unreported `item/completed` is a row that never closes, and an
     * unreported `turn/completed` is a thread that works forever.
     */
    case "view/gap":
      void replayViewGap(attachment, runtime, params);
      return;
    case "approval/requested":
      openApprovalInteraction(attachment, runtime, params);
      return;
    /**
     * A non-terminal approval whose pending view changed: the stage bb answered
     * is resolved and the next one is now current. Muse re-delivers the whole
     * request here, so this is where a multi-stage command keeps moving.
     */
    case "approval/updated":
      advanceApprovalInteraction(attachment, runtime, params);
      return;
    case "userInput/requested":
      openUserInputInteraction(attachment, runtime, params);
      return;
    case "approval/resolved": {
      const approvalId = (params as { approvalId?: unknown }).approvalId;
      if (typeof approvalId === "string") {
        runtime.pendingApprovals.delete(approvalId);
        runtime.approvalDecisions.delete(approvalId);
      }
      return;
    }
    case "userInput/settled": {
      const userInputId = (params as { userInputId?: unknown }).userInputId;
      if (typeof userInputId === "string") {
        runtime.pendingUserInputs.delete(userInputId);
      }
      return;
    }
    case "session/approvalModeChanged": {
      const mode = (params as { mode?: unknown }).mode;
      if (typeof mode === "string") {
        runtime.approvalMode = mode;
        emitDeltas(attachment, [sessionStateDelta(attachment)]);
      }
      return;
    }
    case "session/modelChanged": {
      const modelId = (params as { modelId?: unknown }).modelId;
      if (typeof modelId === "string") {
        runtime.modelId = modelId;
        emitDeltas(attachment, [sessionStateDelta(attachment)]);
      }
      return;
    }
    default:
      break;
  }

  foldViewNotification(attachment, runtime, method, params);
}

/**
 * Folds one view notification into bb's timeline. Push and a replayed page both
 * arrive here, because a terminal bb reads back is owed everything a terminal
 * bb was handed is owed: the same boundary, the same typed failure, and the
 * same rerun of the prompt that hit a condition bb knows how to clear.
 */
function foldViewNotification(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  method: string,
  params: unknown,
): void {
  const recovery =
    method === "turn/completed" ? onTurnCompleted(attachment, params) : null;

  emitDeltas(attachment, runtime.translator.onNotification(method, params));

  /** After the failed turn's boundary, so the transcript reads in order. */
  if (recovery !== null) {
    void rerunFailedTurn(attachment, recovery.turn, recovery.reason);
  }
}

/**
 * A turn's terminal is where bb learns the session can no longer run: MSP
 * reports mid-turn failures here, never as a JSON-RPC error. Muse names the
 * condition in the message, and for the ones bb knows how to clear the prompt
 * that hit one is owed a rerun on the rebuilt session — leaving it for the user
 * to notice and retype is how a turn silently disappears.
 */
function onTurnCompleted(
  attachment: MuseAttachment,
  params: unknown,
): { turn: InFlightTurn; reason: string } | null {
  const classified = classifyTurnFailure(params);
  if (classified.hint !== null) {
    notify(BRIDGE_NOTIFICATION_METHODS.providerRecovery, {
      threadId: attachment.threadId,
      ...classified.hint,
    });
  }

  const turnId = (params as { turnId?: unknown }).turnId;
  const settled = attachment.inFlightTurn;
  /**
   * Matched on the command id as well as the turn id, and on nothing at all
   * while the turn is still unnamed: MSP derives a turn id from the command id
   * that opened it, and bb keeps one turn per thread on the wire, so a terminal
   * arriving before Muse's reply can only belong to the turn bb just sent.
   */
  const settledThisTurn =
    settled !== null &&
    typeof turnId === "string" &&
    (settled.providerTurnId === null ||
      settled.providerTurnId === turnId ||
      settled.commandId === turnId);
  if (settledThisTurn) {
    attachment.inFlightTurn = null;
  }

  if (classified.restart !== null) {
    attachment.restartBeforeNextTurn = classified.restart;
  }
  if (
    !classified.rerun ||
    classified.restart === null ||
    !settledThisTurn ||
    settled.reran ||
    attachment.closing
  ) {
    return null;
  }
  return { turn: settled, reason: classified.restart.reason };
}

/**
 * Reruns the prompt whose turn Muse could not finish. Once: a rebuild that does
 * not clear the condition is a real failure, and a bridge that kept resubmitting
 * would spend the user's tokens in a loop.
 */
async function rerunFailedTurn(
  attachment: MuseAttachment,
  turn: InFlightTurn,
  reason: string,
): Promise<void> {
  emitDeltas(attachment, [
    {
      kind: "provider.warning",
      summary: "Muse could not finish that turn; bb is running it again",
      details: `${reason}. Your prompt was kept and resubmitted — nothing was dropped.`,
    },
  ]);
  await submitTurn({
    attachment,
    input: turn.input,
    options: turn.options,
    reran: true,
  });
}

function handleChildRequest(
  threadId: string,
  serial: number,
  method: string,
  params: unknown,
): void {
  const runtime = liveRuntime(threadId, serial);
  const attachment = attachments.get(threadId);
  if (runtime === null || attachment === undefined) {
    return;
  }
  if (method === "approval/request") {
    openApprovalInteraction(attachment, runtime, params);
    return;
  }
  if (method === "approval/update") {
    advanceApprovalInteraction(attachment, runtime, params);
    return;
  }
  if (method === "userInput/request") {
    openUserInputInteraction(attachment, runtime, params);
  }
}

function handleChildExit(
  threadId: string,
  serial: number,
  info: MspExitInfo,
): void {
  const runtime = liveRuntime(threadId, serial);
  const attachment = attachments.get(threadId);
  if (runtime === null || attachment === undefined) {
    return;
  }
  const message = `muse serve exited (code ${info.code ?? "null"}, signal ${
    info.signal ?? "null"
  })${info.stderrTail === "" ? "" : `: ${info.stderrTail}`}`;

  const reason = "Muse exited; bb restored the session on a fresh process";
  emitDeltas(attachment, [
    {
      kind: "provider.error",
      message,
      settlesTurn: false,
      threadScoped: true,
      category: "internal",
      errorInfo: {
        category: "internal",
        providerCode: "childExited",
        httpStatusCode: null,
      },
    },
  ]);
  emitDeltas(attachment, runtime.translator.settleOpenTurns("failed", message));
  releaseRuntime(attachment, { kill: false });
  attachment.restartBeforeNextTurn = { reason, fresh: false };
  notify(BRIDGE_NOTIFICATION_METHODS.error, {
    threadId: attachment.threadId,
    ...(attachment.providerSessionId === null
      ? {}
      : { providerThreadId: attachment.providerSessionId }),
    message,
  });

  /**
   * A child that dies mid-turn loses the prompt exactly as a classified failure
   * does, and this rebuild resumes the session, so the rerun starts from the
   * work the dead child had already recorded.
   */
  const interrupted = attachment.inFlightTurn;
  attachment.inFlightTurn = null;
  if (interrupted !== null && !interrupted.reran && !attachment.closing) {
    void rerunFailedTurn(attachment, interrupted, reason);
  }
}

/**
 * Muse namespaces an MCP tool as `mcp__<server>__<tool>` (and shows it dotted),
 * so a name is matched back to the tool bb declared.
 */
export function stripMcpPrefix(tool: string): string {
  const match = /^mcp__[^_]+(?:_[^_]+)*?__(?<name>.+)$/u.exec(tool);
  if (match?.groups?.name !== undefined) {
    return match.groups.name;
  }
  const dotted = /^mcp__[A-Za-z0-9_]+\.(?<name>.+)$/u.exec(tool);
  return dotted?.groups?.name ?? tool;
}

/**
 * bb's own plumbing must not read as a decision for the user: Muse's sandbox
 * gating the loopback connection to the tool proxy this bridge started, and
 * Muse gating a tool bb injected, which bb already governs on its own side.
 */
/**
 * The decision bb's own policy already carries, or `null` where the policy
 * names the user as the reviewer and the question is genuinely theirs.
 *
 * Selecting Muse's `allowAll` is only half a policy. `allowAll` governs the
 * rules Muse's grammar can match, and a shell command it cannot statically
 * canonicalise — a `$(…)` substitution, a `${VAR}`, a pipeline, a heredoc, a
 * loop — escalates to a human whatever the mode says. Nearly every command an
 * agent actually writes is one of those, which is why this provider asked for
 * permission where the first-party ones never do: the bridge was forwarding a
 * question bb had already answered.
 *
 * bb's policy has two axes and this reads both. `approvalReviewer` decides who
 * answers an ordinary call: `automatic` and `full` are the bridge, `user` is
 * the user. `permissionEscalation` decides only what happens when the agent
 * reaches past its permission scope, which is what Muse's own `protectedWrite`
 * and `judgeEscalated` flags mark — so under `auto` those still reach the user
 * when bb asked for `ask`, and are refused outright when it asked for `deny`.
 * `full` has no scope to leave and no reviewer, so nothing there reaches anyone.
 */
function policyAnswerFor(
  attachment: MuseAttachment,
  request: MspApprovalRequestParams,
): PendingInteractionApprovalDecision | null {
  if (attachment.construction.approvalMode !== MUSE_APPROVAL_ALLOW_ALL) {
    return null;
  }
  const escalated =
    request.judgeEscalated === true || request.protectedWrite === true;
  if (!escalated) {
    return "allow_once";
  }
  switch (attachment.construction.escalation) {
    case "deny":
      return "deny";
    case "ask":
      return null;
    default:
      /** `full`: no scope to escalate out of, and no reviewer to ask. */
      return "allow_once";
  }
}

function isBridgeInfrastructureApproval(
  attachment: MuseAttachment,
  request: MspApprovalRequestParams,
): boolean {
  const subject = request.subject;
  if (
    subject.kind === "network" &&
    (subject.host === "127.0.0.1" || subject.host === "localhost") &&
    toolProxy !== null &&
    subject.port === toolProxy.port
  ) {
    return true;
  }
  const tool = subject.toolName ?? request.toolName;
  return attachment.construction.toolNames.includes(stripMcpPrefix(tool));
}

function openApprovalInteraction(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  params: unknown,
): void {
  const parsed = mspApprovalRequestParamsSchema.safeParse(params);
  if (!parsed.success) {
    /**
     * An approval bb cannot read is still an approval Muse is holding a tool
     * call for. Every path out of here answers Muse or settles the turn.
     */
    void failApproval(
      attachment,
      runtime,
      `bb could not read Muse's approval request (${parsed.error.message.slice(0, 200)})`,
    );
    return;
  }
  const request = parsed.data;
  if (
    runtime.pendingApprovals.has(request.approvalId) ||
    runtime.approvalsInFlight.has(request.approvalId)
  ) {
    return;
  }

  /** A later stage of a command bb has already been answered on. */
  const carried = runtime.approvalDecisions.get(request.approvalId);
  if (carried !== undefined) {
    void driveApproval(attachment, runtime, request, carried);
    return;
  }
  if (isBridgeInfrastructureApproval(attachment, request)) {
    void driveApproval(attachment, runtime, request, "allow_for_session");
    return;
  }
  const settled = policyAnswerFor(attachment, request);
  if (settled !== null) {
    void driveApproval(attachment, runtime, request, settled);
    return;
  }
  const payload = approvalPayloadFromMsp(request);
  if (payload === null) {
    void driveApproval(attachment, runtime, request, "deny");
    return;
  }
  runtime.pendingApprovals.set(request.approvalId, request);

  void sendRuntimeRequest(BRIDGE_INBOUND_REQUEST_METHODS.interactionRequest, {
    providerThreadId: runtime.sessionId ?? attachment.threadId,
    threadId: attachment.threadId,
    turnId: request.turnId,
    payload,
    providerNativeIds: true,
  })
    .then((resolution) => {
      runtime.pendingApprovals.delete(request.approvalId);
      return driveApproval(
        attachment,
        runtime,
        request,
        approvalDecisionFrom(resolution),
      );
    })
    .catch((error: unknown) => {
      /**
       * bb could not put the question to the user. Muse is still holding the
       * tool call, so the approval is refused rather than abandoned, and the
       * reason is reported: a prompt that silently never appears is the one
       * failure that reads, from the outside, as the agent simply working.
       */
      runtime.pendingApprovals.delete(request.approvalId);
      emitDeltas(attachment, [
        {
          kind: "provider.error",
          message: `bb could not present Muse's approval for ${describeApprovalSubject(request)}: ${
            error instanceof Error ? error.message : String(error)
          }`,
          settlesTurn: false,
          threadScoped: false,
          category: "internal",
          errorInfo: {
            category: "internal",
            providerCode: "approvalUnpresentable",
            httpStatusCode: null,
          },
        },
      ]);
      return driveApproval(attachment, runtime, request, "deny");
    });
}

/**
 * A resumed session can still be holding an approval opened by the process that
 * died under it, and Muse does not re-announce what it has already recorded. So
 * the pending fold is read once on resume and whatever is still open goes back
 * in front of the user, rather than the thread reattaching to a turn that is
 * quietly waiting on a question nobody was asked.
 */
async function reopenPendingInteractions(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
): Promise<void> {
  let result;
  try {
    result = await runtime.connection.request({
      method: MSP_METHODS.approvalListPending,
      params: { sessionId: runtime.sessionId },
      resultSchema: mspApprovalListPendingResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
  } catch {
    /** A host without the fold is a host with nothing to reopen. */
    return;
  }
  if (liveRuntime(attachment.threadId, runtime.serial) !== runtime) {
    return;
  }
  for (const entry of result.approvals ?? []) {
    openApprovalInteraction(attachment, runtime, entry);
  }
  for (const entry of result.userInputs ?? []) {
    openUserInputInteraction(attachment, runtime, entry);
  }
}

/**
 * Muse advanced a non-terminal approval to its next requirement.
 *
 * The chain in `driveApproval` re-reads the pending fold itself, so an update
 * that lands while it is walking is redundant; an update that lands while bb is
 * still asking the user is redundant too, because that answer is applied to
 * whichever requirement is current by then. What is left is an approval whose
 * stage moved on its own — a policy resolving a later fragment — which needs
 * the carried decision applied, or a fresh prompt if there is none.
 */
function advanceApprovalInteraction(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  params: unknown,
): void {
  const parsed = mspApprovalRequestParamsSchema.safeParse(params);
  if (!parsed.success) {
    return;
  }
  const request = parsed.data;
  if (
    runtime.approvalsInFlight.has(request.approvalId) ||
    runtime.pendingApprovals.has(request.approvalId)
  ) {
    return;
  }
  const carried = runtime.approvalDecisions.get(request.approvalId);
  if (carried !== undefined) {
    void driveApproval(attachment, runtime, request, carried);
    return;
  }
  openApprovalInteraction(attachment, runtime, params);
}

function approvalDecisionFrom(
  resolution: unknown,
): PendingInteractionApprovalDecision {
  const decision =
    typeof resolution === "object" &&
    resolution !== null &&
    "decision" in resolution
      ? (resolution as { decision: unknown }).decision
      : null;
  return decision === "allow_once" || decision === "allow_for_session"
    ? decision
    : "deny";
}

/**
 * One command line, so a chain longer than this is a protocol fault rather than
 * a long command — and looping on it would hold the turn open just as silently
 * as never answering at all.
 */
const MAX_APPROVAL_STAGES = 64;

/**
 * Walks an approval to its terminal.
 *
 * `approval/decide` settles one *stage*: its `terminal` flag reports the whole
 * approval, and a `false` means Muse is still holding the tool call and owes
 * the next requirement. A client that answers the first stage and stops leaves
 * the turn parked forever with nothing on screen but the approval bb already
 * resolved — so the decision bb collected is carried across every remaining
 * stage of the same command, and the pending fold, not a notification, is what
 * names the requirement to answer next.
 */
async function driveApproval(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  request: MspApprovalRequestParams,
  decision: PendingInteractionApprovalDecision,
): Promise<void> {
  if (runtime.approvalsInFlight.has(request.approvalId)) {
    return;
  }
  runtime.approvalsInFlight.add(request.approvalId);
  runtime.approvalDecisions.set(request.approvalId, decision);
  try {
    let current = request;
    for (let stage = 0; stage < MAX_APPROVAL_STAGES; stage += 1) {
      if (runtime.closing) {
        return;
      }
      const outcome = await decideApprovalStage(runtime, current, decision);
      if (outcome.kind === "settled") {
        return;
      }
      if (outcome.kind === "failed") {
        await failApproval(attachment, runtime, outcome.message);
        return;
      }
      const next = await pendingApprovalRequest(runtime, request.approvalId);
      if (next === null) {
        /** Muse settled it while bb was reading: nothing is owed. */
        return;
      }
      current = next;
    }
    await failApproval(
      attachment,
      runtime,
      `Muse asked for more than ${String(MAX_APPROVAL_STAGES)} approval stages on one command`,
    );
  } catch (error) {
    await failApproval(
      attachment,
      runtime,
      `bb could not finish answering Muse's approval: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  } finally {
    runtime.approvalsInFlight.delete(request.approvalId);
  }
}

type ApprovalStageOutcome =
  | { kind: "settled" }
  | { kind: "continue" }
  | { kind: "failed"; message: string };

async function decideApprovalStage(
  runtime: MuseRuntime,
  request: MspApprovalRequestParams,
  decision: PendingInteractionApprovalDecision,
): Promise<ApprovalStageOutcome> {
  const choiceId = chooseApprovalChoiceId(request.availableChoices, decision);
  if (choiceId === null) {
    return {
      kind: "failed",
      message: `Muse offered no "${decision}" choice for ${describeApprovalSubject(request)}`,
    };
  }
  try {
    const result = await runtime.connection.request({
      method: MSP_METHODS.approvalDecide,
      params: {
        commandId: uuidV7(),
        sessionId: runtime.sessionId,
        approvalId: request.approvalId,
        requirementId: request.currentRequirementId,
        choiceId,
      },
      resultSchema: mspApprovalDecideResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    /**
     * An omitted flag is read as "not done": the pending fold settles the
     * question either way, and a client that guesses "done" parks the turn.
     */
    return result.terminal === true ? { kind: "settled" } : { kind: "continue" };
  } catch (error) {
    if (error instanceof MspExitedError) {
      /** The child's exit owns the turn from here. */
      return { kind: "settled" };
    }
    if (error instanceof MspRequestError) {
      if (
        error.kind === "approvalAlreadyResolved" ||
        error.kind === "approvalNotFound"
      ) {
        return { kind: "settled" };
      }
      /** The stage advanced under bb; re-read the fold and answer that one. */
      if (error.kind === "approvalRequirementStale") {
        return { kind: "continue" };
      }
    }
    return {
      kind: "failed",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * The requirement Muse is waiting on now, read from the pending fold rather
 * than inferred from the request bb happens to be holding.
 */
async function pendingApprovalRequest(
  runtime: MuseRuntime,
  approvalId: string,
): Promise<MspApprovalRequestParams | null> {
  const result = await runtime.connection.request({
    method: MSP_METHODS.approvalListPending,
    params: { sessionId: runtime.sessionId },
    resultSchema: mspApprovalListPendingResultSchema,
    timeoutMs: COMMAND_TIMEOUT_MS,
  });
  for (const entry of result.approvals ?? []) {
    const parsed = mspApprovalRequestParamsSchema.safeParse(entry);
    if (parsed.success && parsed.data.approvalId === approvalId) {
      return parsed.data;
    }
  }
  return null;
}

function describeApprovalSubject(request: MspApprovalRequestParams): string {
  const subject = request.subject;
  const detail =
    subject.command ?? subject.path ?? subject.target ?? subject.host ?? null;
  const tool = subject.toolName ?? request.toolName;
  return detail === null ? tool : `${tool}: ${detail.slice(0, 120)}`;
}

/**
 * An approval bb cannot answer is reported and the turn is interrupted. Muse
 * holds the tool call until its approval reaches a terminal, so the alternative
 * is a thread that reads as working and never moves again.
 */
async function failApproval(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  message: string,
): Promise<void> {
  const detail = `${message}. bb interrupted the turn rather than leave it waiting on an approval it cannot answer.`;
  emitDeltas(attachment, [
    {
      kind: "provider.error",
      message: detail,
      settlesTurn: false,
      threadScoped: false,
      category: "internal",
      errorInfo: {
        category: "internal",
        providerCode: "approvalUnanswerable",
        httpStatusCode: null,
      },
    },
  ]);
  if (runtime.closing) {
    return;
  }
  await interruptAttachment(attachment, null);
}

function openUserInputInteraction(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  params: unknown,
): void {
  const parsed = mspUserInputRequestParamsSchema.safeParse(params);
  if (!parsed.success) {
    return;
  }
  const request = parsed.data;
  if (runtime.pendingUserInputs.has(request.userInputId)) {
    return;
  }
  const payload = userQuestionPayloadFromMsp(request);
  if (payload === null) {
    /**
     * A prompt bb cannot render is cancelled, not dropped: Muse holds the tool
     * call open until the prompt settles, and the model is told a cancelled
     * question in a sentence, where a parked turn says nothing at all.
     */
    void settleUserInput(runtime, request, null);
    return;
  }
  runtime.pendingUserInputs.set(request.userInputId, request);

  void sendRuntimeRequest(BRIDGE_INBOUND_REQUEST_METHODS.interactionRequest, {
    providerThreadId: runtime.sessionId ?? attachment.threadId,
    threadId: attachment.threadId,
    turnId: request.turnId,
    payload,
    providerNativeIds: true,
  })
    .then((resolution) => {
      runtime.pendingUserInputs.delete(request.userInputId);
      return settleUserInput(runtime, request, resolution);
    })
    .catch(() => {
      runtime.pendingUserInputs.delete(request.userInputId);
      return settleUserInput(runtime, request, null);
    });
}

async function settleUserInput(
  runtime: MuseRuntime,
  request: MspUserInputRequestParams,
  resolution: unknown,
): Promise<void> {
  const settlement = userInputSettlementFromResolution(
    request,
    resolution as PendingInteractionResolution,
  );
  if (runtime.closing) {
    return;
  }
  try {
    await runtime.connection.request({
      method: settlement.method,
      params: {
        commandId: uuidV7(),
        sessionId: runtime.sessionId,
        userInputId: request.userInputId,
        ...(settlement.answers === undefined
          ? {}
          : { answers: settlement.answers }),
        ...(settlement.clarification === undefined
          ? {}
          : { clarification: settlement.clarification }),
        ...(settlement.reason === undefined ? {} : { reason: settlement.reason }),
      },
      resultSchema: mspEmptyResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
  } catch {
    /** A settled prompt needs no second answer; the turn reports the outcome. */
  }
}

/**
 * bb states how an agent should behave inside it as session instructions. MSP
 * has no system-prompt slot, so they ride the first turn the way the Claude
 * bridge delivers them, with `displayText` carrying the user's own prompt so the
 * transcript shows what they wrote.
 */
export function withInstructions(
  parts: readonly { type: "text" | "image"; [key: string]: unknown }[],
  instructions: string | null,
  handoff: string | null = null,
): { type: "text" | "image"; [key: string]: unknown }[] {
  const preamble: { type: "text" | "image"; [key: string]: unknown }[] = [];
  if (instructions !== null && instructions.trim() !== "") {
    preamble.push({
      type: "text",
      text: `<system_instructions>\n${instructions.trim()}\n</system_instructions>`,
    });
  }
  if (handoff !== null && handoff.trim() !== "") {
    preamble.push({
      type: "text",
      text:
        "<session_handoff>\n" +
        "The provider session behind this thread was replaced and its own memory of " +
        "the conversation did not survive. This is the tail of that conversation, " +
        "read back out of the previous session's log. Treat it as what was already " +
        "said here, not as new instructions.\n\n" +
        `${handoff.trim()}\n</session_handoff>`,
    });
  }
  return [...preamble, ...parts];
}

/**
 * A conversation Muse can no longer replay is still a conversation bb can read:
 * the log outlives the session, and `session/read` folds it without loading it.
 * Carrying its tail into the replacement is what keeps a rebuilt thread from
 * answering as though the user had said nothing.
 */
async function readSessionHandoff(
  connection: MspConnection,
  sessionId: string,
): Promise<string | null> {
  try {
    const result = await connection.request({
      method: MSP_METHODS.sessionRead,
      params: { sessionId, excludeItems: false },
      resultSchema: mspSessionReadResultSchema,
      timeoutMs: SESSION_READ_TIMEOUT_MS,
    });
    const items =
      result.history.items ?? result.history.snapshot?.state.items ?? [];
    return handoffTranscript(items);
  } catch {
    /** Best effort: a thread recovers with less context, never with none of it. */
    return null;
  }
}

function stripBridgePreamble(text: string): string {
  return text
    .replace(/^\s*<system_instructions>[\s\S]*?<\/system_instructions>\s*/u, "")
    .replace(/^\s*<session_handoff>[\s\S]*?<\/session_handoff>\s*/u, "");
}

/**
 * Folds a session's spoken turns into a transcript, newest first until the
 * budget runs out, then back into reading order. Only what was said: tool calls
 * and reasoning are the session's own bookkeeping, and reasoning is the thing
 * the replacement cannot accept in the first place.
 */
export function handoffTranscript(
  items: readonly { kind: string; text?: string; displayText?: string }[],
): string | null {
  const lines: string[] = [];
  let budget = HANDOFF_CHAR_BUDGET;
  for (let index = items.length - 1; index >= 0 && budget > 0; index -= 1) {
    const item = items[index];
    const speaker =
      item.kind === "userMessage"
        ? "user"
        : item.kind === "agentMessage"
          ? "assistant"
          : null;
    /**
     * A user message carries whatever bb wrapped around the prompt — its own
     * session instructions, an earlier handoff — and Muse keeps the user's own
     * words in `displayText`. Sending the wrappers back would hand the new
     * session a second copy of instructions it is being given anyway.
     */
    const text = (
      speaker === "user"
        ? (item.displayText ?? stripBridgePreamble(item.text ?? ""))
        : (item.text ?? "")
    ).trim();
    if (speaker === null || text === "") {
      continue;
    }
    const kept =
      text.length > budget ? `…${text.slice(text.length - budget)}` : text;
    budget -= kept.length;
    lines.push(`${speaker}: ${kept}`);
  }
  return lines.length === 0 ? null : lines.reverse().join("\n\n");
}

function promptDisplayText(input: readonly PromptInput[]): string | undefined {
  const text = input
    .filter((item): item is Extract<PromptInput, { type: "text" }> =>
      item.type === "text",
    )
    .map((item) => item.text)
    .join("")
    .trim();
  return text === "" ? undefined : text;
}

async function turnInputParts(
  input: readonly PromptInput[],
): Promise<{ type: "text" | "image"; [key: string]: unknown }[]> {
  const parts: { type: "text" | "image"; [key: string]: unknown }[] = [];
  for (const item of input) {
    switch (item.type) {
      case "text":
        if (item.text !== "") {
          parts.push({ type: "text", text: item.text });
        }
        break;
      /**
       * Muse takes an image on the wire and then cannot keep it: the model
       * behind it rejects the session the moment that media is replayed as
       * history — "retained media history is unsupported by target provider
       * `muse`" — which costs the conversation, not just the image. A path the
       * agent can open itself is worth more than an attachment that breaks the
       * session it was attached to.
       */
      case "localImage":
        parts.push({ type: "text", text: `@${item.path}` });
        break;
      case "localFile":
        parts.push({ type: "text", text: `@${item.path}` });
        break;
      case "image":
        parts.push({ type: "text", text: item.url });
        break;
    }
  }
  return parts.length > 0 ? parts : [{ type: "text", text: "" }];
}

function reasoningEffortFor(level: string | undefined): string | undefined {
  if (level === undefined) {
    return undefined;
  }
  return MUSE_REASONING_EFFORTS[level as keyof typeof MUSE_REASONING_EFFORTS];
}

/**
 * The one place a turn may run from. A rebuild is owed when the child is gone,
 * when a failure asked for one, or when the execution options changed in a way
 * Muse only reads at session construction — the same three reasons codex
 * rebuilds, plus Muse's inability to carry reasoning across a route change.
 */
async function liveRuntimeForTurn(args: {
  attachment: MuseAttachment;
  options: BridgeExecutionOptions;
}): Promise<MuseRuntime> {
  const { attachment } = args;
  cancelIdleShutdown(attachment);

  const nextConstruction = buildConstruction({
    cwd: attachment.cwd,
    options: args.options,
    instructionMode: attachment.construction.instructionMode,
    dynamicTools: attachment.dynamicTools,
  });
  const nextSignature = constructionSignature(nextConstruction);

  const runtime = attachment.runtime;
  const restart = attachment.restartBeforeNextTurn;
  const optionsChanged = nextSignature !== attachment.constructionSignature;

  if (
    runtime !== null &&
    !runtime.closing &&
    !runtime.connection.exited &&
    restart === null &&
    !optionsChanged
  ) {
    return runtime;
  }

  if (runtime !== null && !runtime.closing) {
    emitDeltas(
      attachment,
      runtime.translator.settleOpenTurns(
        "interrupted",
        "The Muse session was replaced",
      ),
    );
  }

  attachment.restartBeforeNextTurn = null;
  attachment.construction = nextConstruction;
  attachment.constructionSignature = nextSignature;

  const fresh = restart?.fresh === true;
  const resumeId = attachment.providerSessionId;
  const request: ConstructionRequest =
    fresh || resumeId === null
      ? { kind: "fresh" }
      : { kind: "resume", providerThreadId: resumeId };

  const reason =
    restart?.reason ??
    (optionsChanged
      ? "Execution settings changed; the Muse session was rebuilt to apply them"
      : "Muse exited; bb restored the session on a fresh process");

  const replacement = await constructRuntime({
    attachment,
    options: args.options,
    request,
  });
  notify(BRIDGE_NOTIFICATION_METHODS.sessionReplaced, {
    threadId: attachment.threadId,
    providerThreadId: replacement.sessionId,
    reason,
    contextLost: fresh,
  });
  if (fresh) {
    /**
     * A fresh session has never seen bb's session instructions — those rode the
     * first turn of the session just discarded — so they are owed again, along
     * with whatever of the discarded conversation survives as plain text.
     */
    attachment.pendingInstructions = attachment.instructions;
    attachment.pendingHandoff =
      resumeId === null
        ? null
        : await readSessionHandoff(replacement.connection, resumeId);
    emitDeltas(attachment, [
      {
        kind: "provider.warning",
        summary: "Muse started a fresh session for this thread",
        details:
          `${reason}. Durable bb state is untouched, and ` +
          (attachment.pendingHandoff === null
            ? "the in-session conversation could not be read back."
            : "the conversation so far is carried into the new session as a transcript."),
      },
    ]);
  }
  return replacement;
}

let zeroWorkCounter = 0;

/**
 * A prompt the provider handles without doing work must still settle, or the
 * thread hangs on accepted input that never opens a turn.
 */
function scheduleZeroWorkSettlement(args: {
  attachment: MuseAttachment;
  runtime: MuseRuntime;
  clientRequestId: string;
}): void {
  const { attachment, runtime, clientRequestId } = args;
  /**
   * The turn count as this prompt went out. A turn that opens after it — over
   * push, or recovered by a read — is this prompt's work, and no settlement may
   * be invented over it.
   */
  const openedBefore = runtime.turnsOpened;
  const timer = setTimeout(() => {
    void settleIfNoWork(attachment, runtime, clientRequestId, openedBefore);
  }, ZERO_WORK_SETTLEMENT_GRACE_MS);
  timer.unref?.();
}

/**
 * "No turn opened" and "no turn was reported" look identical from here, and
 * they are opposites: the first is a prompt Muse answered without working, the
 * second is a turn running right now on a session whose view has stopped
 * reaching bb. Fabricating a completed turn for the second is worse than
 * hanging — the thread reports success for work that is still going.
 *
 * So the view is read before anything is invented. A page settles it: silence
 * from a session that has nothing to say is empty, and silence from one that
 * has stopped talking is not.
 */
async function settleIfNoWork(
  attachment: MuseAttachment,
  runtime: MuseRuntime,
  clientRequestId: string,
  openedBefore: number,
): Promise<void> {
  const settled = (live: MuseRuntime | null): boolean =>
    live === null ||
    live.openTurnIds.size > 0 ||
    live.turnsOpened !== openedBefore;
  {
    const live = liveRuntime(attachment.threadId, runtime.serial);
    if (settled(live)) {
      return;
    }
    await reconcileView({ attachment, runtime });
  }
  {
    const live = liveRuntime(attachment.threadId, runtime.serial);
    if (settled(live)) {
      return;
    }
    zeroWorkCounter += 1;
    const providerTurnId = `zero-work-${zeroWorkCounter}`;
    emitDeltas(attachment, [
      { kind: "turn.open", providerTurnId },
      { kind: "input.accepted", clientRequestId, providerTurnId },
      { kind: "turn.boundary", providerTurnId, status: "completed" },
    ]);
  }
}

async function submitTurn(args: {
  attachment: MuseAttachment;
  input: readonly PromptInput[];
  options: BridgeExecutionOptions;
  clientRequestId?: string;
  /** Set on bb's own rerun of a failed turn, which is never rerun again. */
  reran?: boolean;
}): Promise<void> {
  const { attachment, options } = args;
  let acceptedEmitted = false;
  let submitted: InFlightTurn | null = null;
  let owedInstructions: string | null = null;
  let owedHandoff: string | null = null;

  try {
    const runtime = await liveRuntimeForTurn({ attachment, options });

    if (args.clientRequestId !== undefined) {
      emitDeltas(attachment, [
        { kind: "input.accepted", clientRequestId: args.clientRequestId },
      ]);
      acceptedEmitted = true;
    }

    if (isStandaloneBuiltinCompactCommand(args.input)) {
      await runtime.connection.request({
        method: MSP_METHODS.sessionCompact,
        params: { commandId: uuidV7(), sessionId: runtime.sessionId },
        resultSchema: mspCommandAckSchema,
        timeoutMs: COMMAND_TIMEOUT_MS,
      });
      emitDeltas(attachment, [
        { kind: "turn.open" },
        { kind: "turn.boundary", status: "completed" },
      ]);
      return;
    }

    owedInstructions = attachment.pendingInstructions;
    owedHandoff = attachment.pendingHandoff;
    const input = withInstructions(
      await turnInputParts(args.input),
      owedInstructions,
      owedHandoff,
    );
    const displayText =
      owedInstructions === null && owedHandoff === null
        ? undefined
        : promptDisplayText(args.input);
    const reasoningEffort = reasoningEffortFor(options.reasoningLevel);

    /**
     * Recorded before the command goes out, because the turn's terminal can
     * beat the reply that names it: the child's response and its notifications
     * arrive on one stream, and a chunk carrying both is dispatched line by
     * line before any `await` here resumes. A turn recorded only afterwards is
     * a turn whose failure bb cannot attribute — which is how a prompt goes
     * missing. What rode with it is cleared here too, and restored below if
     * the command never reaches Muse at all.
     */
    const commandId = uuidV7();
    submitted = {
      commandId,
      providerTurnId: null,
      input: args.input,
      options,
      reran: args.reran === true,
    };
    attachment.inFlightTurn = submitted;
    attachment.pendingInstructions = null;
    attachment.pendingHandoff = null;

    const started = await runtime.connection.request({
      method: MSP_METHODS.turnStart,
      params: {
        commandId,
        sessionId: runtime.sessionId,
        input,
        ifBusy: "queue",
        ...(displayText === undefined ? {} : { displayText }),
        ...(reasoningEffort === undefined ? {} : { reasoningEffort }),
      },
      resultSchema: mspTurnStartResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
    if (attachment.inFlightTurn === submitted) {
      submitted.providerTurnId = started.turnId;
    }
    /**
     * Muse's reply is authoritative about whether a turn exists, and it is the
     * only place bb learns that before the view says so. A session whose view
     * has stopped accepts the prompt and starts the turn while never reporting
     * `turn/started`, which is indistinguishable from a prompt handled without
     * work — and settling that as a completed turn is how a user's message gets
     * accepted, marked done, and never run.
     *
     * So the turn is opened here, on Muse's word. The translator dedupes the
     * `turn/started` that normally follows, and everything downstream — the
     * watchdog, the abandon logic, `settleOpenTurns` — now sees a turn to
     * account for rather than silence to guess at.
     */
    if (started.startedNewTurn) {
      emitDeltas(attachment, runtime.translator.adoptOpenTurn(started.turnId));
    }
    /**
     * Only a prompt Muse says it started no turn for can be settled as one that
     * needed no work. If it started a turn, the turn is the authority on how
     * this ends — even if the view never reports it, which is a stalled session
     * for the watchdog to settle as a failure, not a completion to invent.
     */
    if (args.clientRequestId !== undefined && !started.startedNewTurn) {
      scheduleZeroWorkSettlement({
        attachment,
        runtime,
        clientRequestId: args.clientRequestId,
      });
    }
  } catch (error) {
    /**
     * Accepted input that never settles leaves bb refusing every later turn on
     * the thread, so every failure on this path closes the turn — including one
     * thrown before the input was ever accepted.
     */
    /** A command Muse never accepted owes nothing back and reruns nothing. */
    if (submitted !== null && attachment.inFlightTurn === submitted) {
      attachment.inFlightTurn = null;
      attachment.pendingInstructions = owedInstructions;
      attachment.pendingHandoff = owedHandoff;
    }
    const message = error instanceof Error ? error.message : String(error);
    const deltas: ThreadDelta[] = [];
    if (!acceptedEmitted && args.clientRequestId !== undefined) {
      deltas.push({
        kind: "input.accepted",
        clientRequestId: args.clientRequestId,
      });
    }
    /**
     * A command that never reached Muse is a bridge-side fault, and it is
     * typed like every other one so bb's recovery reads the same field here
     * as it does on a turn Muse itself failed.
     */
    const errorInfo = museProviderErrorInfo({
      kind: error instanceof MspExitedError ? "launchError" : undefined,
      message,
    });
    deltas.push(
      {
        kind: "provider.error",
        message,
        settlesTurn: true,
        ...(errorInfo === null
          ? {}
          : { errorInfo, category: errorInfo.category }),
      },
      {
        kind: "turn.boundary",
        status: "failed",
        claimIfIdle: true,
        error: { message },
      },
    );
    emitDeltas(attachment, deltas);
    if (error instanceof MspExitedError) {
      notify(BRIDGE_NOTIFICATION_METHODS.providerRecovery, {
        threadId: attachment.threadId,
        kind: "restartRecommended",
        message,
        retryable: true,
      });
    }
  }
}

/**
 * Muse's catalog labels a model with its own id. bb strips the declared brand
 * prefix from what it shows, so an id becomes a title here.
 */
export function museModelDisplayName(entry: {
  modelId: string;
  displayLabel: string;
}): string {
  if (entry.displayLabel !== entry.modelId) {
    return entry.displayLabel;
  }
  return entry.modelId
    .split("-")
    .map((part) =>
      /^[a-z]/u.test(part) ? part.charAt(0).toUpperCase() + part.slice(1) : part,
    )
    .reduce((label, part) => {
      const separator = /^[0-9]/u.test(part) && /[0-9]$/u.test(label) ? "." : " ";
      return label === "" ? part : `${label}${separator}${part}`;
    }, "");
}

function modelFromCatalog(entry: MspModelCatalogEntry): AvailableModel {
  const contextLimit =
    entry.contextLimit === null
      ? ""
      : ` · ${Math.round(entry.contextLimit / 1_000)}K context`;
  return {
    id: entry.modelId,
    model: entry.modelId,
    displayName: museModelDisplayName(entry),
    description: entry.description ?? `Muse Spark${contextLimit}`,
    supportedReasoningEfforts: [
      { reasoningEffort: "low", description: "Fast, shallow reasoning." },
      { reasoningEffort: "medium", description: "Balanced reasoning." },
      { reasoningEffort: "high", description: "Muse Code's default effort." },
      { reasoningEffort: "xhigh", description: "Extra-high reasoning." },
      { reasoningEffort: "max", description: "Muse's native max effort." },
      { reasoningEffort: "ultra", description: "Muse's native ultra effort." },
    ],
    defaultReasoningEffort: MUSE_DEFAULT_REASONING_LEVEL,
    isDefault: entry.isDefault,
  };
}

/**
 * Model listing runs on a child of its own, as codex keeps a separate
 * app-server for it: a catalog read must never disturb, or be disturbed by, a
 * thread's session.
 */
async function maintenanceChild(cwd: string): Promise<MspConnection> {
  if (maintenanceConnection !== null && !maintenanceConnection.exited) {
    return maintenanceConnection;
  }
  if (maintenanceConnectionPromise !== null) {
    return maintenanceConnectionPromise;
  }
  const promise = (async () => {
    const connection = spawnChild({
      posture: {
        disableSandbox: true,
        sandboxNetwork: "enabled",
        trustWorkspace: false,
      },
      cwd,
      env: childEnv(undefined, null),
      recordThreadId: null,
      onNotification: () => {},
      onRequest: () => {},
      onExit: () => {
        if (maintenanceConnection === connection) {
          maintenanceConnection = null;
        }
      },
    });
    try {
      await handshake(connection);
      maintenanceConnection = connection;
      return connection;
    } catch (error) {
      connection.kill();
      throw error;
    }
  })();
  maintenanceConnectionPromise = promise;
  try {
    return await promise;
  } finally {
    if (maintenanceConnectionPromise === promise) {
      maintenanceConnectionPromise = null;
    }
  }
}

async function listModels(cwd: string): Promise<AvailableModel[]> {
  const connection = await maintenanceChild(cwd);
  const result = await connection.request({
    method: MSP_METHODS.modelList,
    resultSchema: mspModelListResultSchema,
    timeoutMs: COMMAND_TIMEOUT_MS,
  });
  const models: AvailableModel[] = [];
  for (const raw of result.models) {
    const parsed = mspModelCatalogEntrySchema.safeParse(raw);
    if (parsed.success) {
      models.push(modelFromCatalog(parsed.data));
    }
  }
  if (models.length > 0 && !models.some((model) => model.isDefault)) {
    models[0] = { ...models[0], isDefault: true };
  }
  return models;
}

function invalidParams(id: JsonRpcId, method: string, issues: unknown): void {
  io.send({
    jsonrpc: "2.0",
    id,
    error: {
      code: BRIDGE_JSON_RPC_ERRORS.INVALID_PARAMS,
      message: `Invalid params for ${method}`,
      data: issues,
    },
  });
}

function registerAttachment(args: {
  threadId: string;
  cwd: string;
  options: BridgeExecutionOptions;
  instructionMode: string;
  dynamicTools: readonly DynamicTool[];
}): MuseAttachment {
  const existing = attachments.get(args.threadId);
  if (existing !== undefined) {
    forgetAttachment(existing);
  }
  const construction = buildConstruction({
    cwd: args.cwd,
    options: args.options,
    instructionMode: args.instructionMode,
    dynamicTools: args.dynamicTools,
  });
  const instructions =
    args.options.instructions !== undefined &&
    args.options.instructions.trim() !== ""
      ? args.options.instructions
      : null;
  const attachment: MuseAttachment = {
    threadId: args.threadId,
    cwd: args.cwd,
    construction,
    constructionSignature: constructionSignature(construction),
    dynamicTools: [...args.dynamicTools],
    instructions,
    pendingInstructions: instructions,
    pendingHandoff: null,
    inFlightTurn: null,
    providerSessionId: null,
    configHome: null,
    runtime: null,
    identityAnnounced: false,
    pendingPreIdentityDeltas: [],
    restartBeforeNextTurn: null,
    idleTimer: null,
    closing: false,
  };
  attachments.set(args.threadId, attachment);
  return attachment;
}

function constructionError(id: JsonRpcId, error: unknown): void {
  io.sendError(
    id,
    BRIDGE_JSON_RPC_ERRORS.BRIDGE_ERROR,
    error instanceof Error ? error.message : String(error),
  );
}

type RequestHandler = (id: JsonRpcId, params: unknown) => Promise<void> | void;

const handlers: Record<string, RequestHandler> = {
  [BRIDGE_REQUEST_METHODS.initialize]: (id, params) => {
    const parsed = initializeParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.initialize, parsed.error.issues);
      return;
    }
    io.sendResult(id, {
      protocolVersion: PROVIDER_BRIDGE_PROTOCOL_VERSION,
      capabilities: {
        grammarVersions: [THREAD_DELTA_GRAMMAR_V3, THREAD_DELTA_GRAMMAR_V3],
        sessionRestore: true,
        threadArchive: false,
        threadRename: false,
        threadGoalClear: false,
        fork: "tip",
        approvalEnforcedBy: "runtime",
        steerMode: "inject",
        skills: { configure: false },
      },
    });
  },

  [BRIDGE_REQUEST_METHODS.modelList]: async (id, params) => {
    const parsed = modelListParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.modelList, parsed.error.issues);
      return;
    }
    io.sendResult(id, {
      models: await listModels(parsed.data.cwd ?? process.cwd()),
      selectedOnlyModels: [],
    });
  },

  [BRIDGE_REQUEST_METHODS.providerHealth]: async (id, params) => {
    const parsed = providerMaintenanceParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(
        id,
        BRIDGE_REQUEST_METHODS.providerHealth,
        parsed.error.issues,
      );
      return;
    }
    io.sendResult(id, await getMuseProviderHealth());
  },

  [BRIDGE_REQUEST_METHODS.providerUsage]: async (id, params) => {
    const parsed = providerMaintenanceParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(
        id,
        BRIDGE_REQUEST_METHODS.providerUsage,
        parsed.error.issues,
      );
      return;
    }
    const options = parseProviderOptions(parsed.data.providerOptions);
    io.sendResult(
      id,
      await getMuseProviderUsage({
        tokenBudget: options.tokenBudget ?? null,
        planLabel: options.planLabel ?? null,
        subscription: await subscriptionUsage.latest(),
      }),
    );
  },

  [BRIDGE_REQUEST_METHODS.providerInstallationStatus]: async (id, params) => {
    const parsed = providerInstallationStatusParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(
        id,
        BRIDGE_REQUEST_METHODS.providerInstallationStatus,
        parsed.error.issues,
      );
      return;
    }
    io.sendResult(id, await getMuseInstallationStatus());
  },

  [BRIDGE_REQUEST_METHODS.providerInstallationRun]: async (id, params) => {
    const parsed = providerInstallationRunParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(
        id,
        BRIDGE_REQUEST_METHODS.providerInstallationRun,
        parsed.error.issues,
      );
      return;
    }
    io.sendResult(id, await getMuseInstallationRun(parsed.data.action));
  },

  [BRIDGE_REQUEST_METHODS.threadStart]: async (id, params) => {
    const parsed = threadStartParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.threadStart, parsed.error.issues);
      return;
    }
    const { threadId, cwd, options, input } = parsed.data;
    const attachment = registerAttachment({
      threadId,
      cwd,
      options,
      instructionMode: parsed.data.instructionMode,
      dynamicTools: parsed.data.dynamicTools ?? [],
    });
    try {
      const runtime = await constructRuntime({
        attachment,
        options,
        request: { kind: "start" },
      });
      io.sendResult(id, {
        providerThreadId: runtime.sessionId,
        sessionRestorable: runtime.sessionLogPath !== null,
      });
    } catch (error) {
      forgetAttachment(attachment);
      constructionError(id, error);
      return;
    }
    if (input !== undefined && input.length > 0) {
      await submitTurn({ attachment, input, options });
    }
  },

  [BRIDGE_REQUEST_METHODS.threadResume]: async (id, params) => {
    const parsed = threadResumeParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(
        id,
        BRIDGE_REQUEST_METHODS.threadResume,
        parsed.error.issues,
      );
      return;
    }
    const { threadId, cwd, options, providerThreadId } = parsed.data;
    const existing = attachments.get(threadId);
    if (
      existing !== undefined &&
      existing.providerSessionId === providerThreadId &&
      existing.runtime !== null &&
      !existing.runtime.closing &&
      !existing.runtime.connection.exited
    ) {
      /**
       * This thread's own child is still live with the session loaded. Reusing
       * it keeps the route, and therefore the session's reasoning history,
       * which a resume onto a fresh process would invalidate.
       */
      cancelIdleShutdown(existing);
      io.sendResult(id, { providerThreadId, sessionRestorable: true });
      return;
    }

    const attachment = registerAttachment({
      threadId,
      cwd,
      options,
      instructionMode: parsed.data.instructionMode,
      dynamicTools: parsed.data.dynamicTools ?? [],
    });
    attachment.providerSessionId = providerThreadId;
    try {
      const runtime = await constructRuntime({
        attachment,
        options,
        request: { kind: "resume", providerThreadId },
      });
      io.sendResult(id, {
        providerThreadId: runtime.sessionId,
        sessionRestorable: runtime.sessionLogPath !== null,
      });
    } catch (error) {
      forgetAttachment(attachment);
      if (
        error instanceof MspRequestError &&
        (error.kind === "sessionNotFound" || error.kind === "sessionAmbiguous")
      ) {
        io.sendError(
          id,
          BRIDGE_JSON_RPC_ERRORS.SESSION_NOT_RESTORABLE,
          `Muse session ${providerThreadId} is no longer on this machine`,
        );
        return;
      }
      constructionError(id, error);
    }
  },

  [BRIDGE_REQUEST_METHODS.threadFork]: async (id, params) => {
    const parsed = threadForkParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.threadFork, parsed.error.issues);
      return;
    }
    if (parsed.data.sourceProviderCheckpointId !== undefined) {
      io.sendError(
        id,
        BRIDGE_JSON_RPC_ERRORS.FORK_CHECKPOINT_UNSUPPORTED,
        "Muse forks at the tip of a session, not at a checkpoint",
      );
      return;
    }
    const { threadId, cwd, options, sourceProviderThreadId } = parsed.data;
    const attachment = registerAttachment({
      threadId,
      cwd,
      options,
      instructionMode: parsed.data.instructionMode,
      dynamicTools: parsed.data.dynamicTools ?? [],
    });
    try {
      const runtime = await constructRuntime({
        attachment,
        options,
        request: { kind: "fork", sourceProviderThreadId },
      });
      io.sendResult(id, {
        providerThreadId: runtime.sessionId,
        sessionRestorable: runtime.sessionLogPath !== null,
      });
    } catch (error) {
      forgetAttachment(attachment);
      constructionError(id, error);
    }
  },

  [BRIDGE_REQUEST_METHODS.turnStart]: async (id, params) => {
    const parsed = turnStartParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.turnStart, parsed.error.issues);
      return;
    }
    const attachment = attachments.get(parsed.data.threadId);
    if (attachment === undefined) {
      io.sendError(
        id,
        BRIDGE_JSON_RPC_ERRORS.BRIDGE_ERROR,
        `No Muse session for thread ${parsed.data.threadId}; send thread/start or thread/resume first`,
      );
      return;
    }
    io.sendResult(id, {});
    await submitTurn({
      attachment,
      input: parsed.data.input,
      options: parsed.data.options,
      clientRequestId: parsed.data.clientRequestId,
    });
  },

  [BRIDGE_REQUEST_METHODS.turnSteer]: async (id, params) => {
    const parsed = turnSteerParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.turnSteer, parsed.error.issues);
      return;
    }
    const attachment = attachments.get(parsed.data.threadId);
    const runtime = attachment?.runtime ?? null;
    if (
      attachment === undefined ||
      runtime === null ||
      runtime.closing ||
      runtime.connection.exited ||
      !runtime.openTurnIds.has(parsed.data.expectedTurnId)
    ) {
      io.sendError(
        id,
        BRIDGE_JSON_RPC_ERRORS.NO_ACTIVE_TURN,
        `Muse turn ${parsed.data.expectedTurnId} is no longer running`,
      );
      return;
    }
    try {
      const input = await turnInputParts(parsed.data.input);
      const reasoningEffort = reasoningEffortFor(
        parsed.data.options.reasoningLevel,
      );
      await runtime.connection.request({
        method: MSP_METHODS.turnSteer,
        params: {
          commandId: uuidV7(),
          sessionId: runtime.sessionId,
          expectedTurnId: parsed.data.expectedTurnId,
          input,
          ...(reasoningEffort === undefined ? {} : { reasoningEffort }),
        },
        resultSchema: mspTurnSteerResultSchema,
        timeoutMs: COMMAND_TIMEOUT_MS,
      });
      emitDeltas(attachment, [
        {
          kind: "input.accepted",
          clientRequestId: parsed.data.clientRequestId,
          providerTurnId: parsed.data.expectedTurnId,
        },
      ]);
      io.sendResult(id, {});
    } catch (error) {
      io.sendError(
        id,
        BRIDGE_JSON_RPC_ERRORS.NO_ACTIVE_TURN,
        error instanceof Error ? error.message : String(error),
        {
          recovery: {
            kind: "staleTurn",
            message: "The Muse turn this steer targeted is gone.",
            retryable: false,
          },
        },
      );
    }
  },

  [BRIDGE_REQUEST_METHODS.threadStop]: async (id, params) => {
    const parsed = threadStopParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(id, BRIDGE_REQUEST_METHODS.threadStop, parsed.error.issues);
      return;
    }
    const { threadId, intent, activeTurnId } = parsed.data;
    const attachment = attachments.get(threadId);
    if (attachment === undefined) {
      io.sendResult(id, {});
      return;
    }

    if (intent === "interrupt") {
      await interruptAttachment(attachment, activeTurnId);
    }

    /**
     * `release` detaches an idle session and must fabricate nothing. The child
     * stays alive so a later turn keeps this session's route; it is reclaimed by
     * the idle timer, by `thread/discard`, or when the bridge shuts down.
     */
    scheduleIdleShutdown(attachment);
    io.sendResult(id, {});
  },

  [BRIDGE_REQUEST_METHODS.threadDiscard]: (id, params) => {
    const parsed = threadDiscardParamsSchema.safeParse(params);
    if (!parsed.success) {
      invalidParams(
        id,
        BRIDGE_REQUEST_METHODS.threadDiscard,
        parsed.error.issues,
      );
      return;
    }
    const attachment = attachments.get(parsed.data.threadId);
    if (attachment !== undefined) {
      forgetAttachment(attachment);
    }
    io.sendResult(id, {});
  },
};

async function interruptAttachment(
  attachment: MuseAttachment,
  activeTurnId: string | null,
): Promise<void> {
  const runtime = attachment.runtime;
  if (runtime === null || runtime.closing || runtime.connection.exited) {
    return;
  }
  const openTurns = [...runtime.openTurnIds];
  if (openTurns.length === 0) {
    return;
  }
  const turnId = activeTurnId ?? openTurns[0];

  try {
    await runtime.connection.request({
      method: MSP_METHODS.turnInterrupt,
      params: {
        commandId: uuidV7(),
        sessionId: runtime.sessionId,
        ...(activeTurnId === null ? {} : { turnId: activeTurnId }),
      },
      resultSchema: mspTurnInterruptResultSchema,
      timeoutMs: COMMAND_TIMEOUT_MS,
    });
  } catch {
    /** Settle locally below; a stop must not wait on a failed interrupt. */
  }

  const settled = await waitForTurnSettlement(
    runtime,
    turnId,
    INTERRUPT_SETTLE_TIMEOUT_MS,
  );
  if (!settled) {
    emitDeltas(
      attachment,
      runtime.translator.settleOpenTurns("interrupted", "Interrupted by bb"),
    );
  }
}

export function handleLine(line: string): void {
  let message: unknown;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (
    typeof message !== "object" ||
    message === null ||
    Array.isArray(message)
  ) {
    return;
  }
  const { id, method, params } = message as {
    id?: unknown;
    method?: unknown;
    params?: unknown;
  };

  if (typeof method !== "string") {
    const response = decodeBridgeJsonRpcResponse(message);
    if (response === null || typeof response.id !== "string") {
      return;
    }
    const pending = pendingRuntimeRequests.get(response.id);
    if (pending === undefined) {
      return;
    }
    pendingRuntimeRequests.delete(response.id);
    if ("error" in response) {
      pending.reject(
        new Error(response.error.message ?? "bb rejected a bridge request"),
      );
      return;
    }
    pending.resolve(response.result);
    return;
  }

  if (typeof id !== "string" && typeof id !== "number") {
    return;
  }
  const handler = handlers[method];
  if (handler === undefined) {
    io.sendError(
      id,
      BRIDGE_JSON_RPC_ERRORS.METHOD_NOT_FOUND,
      `Method not found: ${method}`,
    );
    return;
  }
  runBridgeRequest({
    request: { id, method, params },
    sendError: io.sendError,
    handleRequest: async (request) => {
      await handler(request.id, request.params);
    },
  });
}

function shutdown(): void {
  toolProxy?.close();
  toolProxy = null;
  maintenanceConnection?.kill();
  maintenanceConnection = null;
  for (const attachment of [...attachments.values()]) {
    forgetAttachment(attachment);
  }
}

export const experimental_providerBridge = experimental_defineProviderBridge({
  handleLine,
  start(context) {
    bridgeDataDir = context.dataDir;
  },
  onClose: shutdown,
  onSigterm: shutdown,
  onSigint: shutdown,
});
