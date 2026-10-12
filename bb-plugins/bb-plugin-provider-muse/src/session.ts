import type {
  BridgeExecutionOptions,
  DynamicTool,
  PendingInteractionApprovalDecision,
  PromptInput,
  ThreadDelta,
} from "@get-bb/plugin-sdk/provider-bridge";
import type { MspConnection } from "./msp/connection.js";
import { MuseTranslator } from "./translate.js";
import type { MspApprovalRequestParams, MspUserInputRequestParams } from "./msp/schemas.js";

/**
 * The bridge keeps the same two-layer shape the first-party bridges keep.
 *
 * An **attachment** is what bb owns: one per thread, durable for as long as bb
 * holds the thread, carrying the provider session id, the construction inputs,
 * and the reason a rebuild is owed. A **runtime** is the live `muse serve`
 * process and the loaded session inside it — disposable, replaced whenever the
 * child dies, the execution options change, or Muse refuses to carry on.
 *
 * Every asynchronous callback carries the runtime's `serial`, so a reply that
 * arrives after a replacement can be dropped instead of mutating the session
 * that took its place.
 */

export interface HostPosture {
  disableSandbox: boolean;
  sandboxNetwork: "enabled" | "proxy-only" | "restricted";
  trustWorkspace: boolean;
}

export interface SessionConstruction {
  cwd: string;
  posture: HostPosture;
  approvalMode: string;
  /**
   * What bb wants done when the agent asks to go beyond its permission scope:
   * `ask` puts it to the user, `deny` refuses it, `null` is `full`, which has
   * no scope to leave. It is policy, not session shape, so it stays out of
   * `constructionSignature` — changing it must not cost a session rebuild.
   */
  escalation: string | null;
  model: string | undefined;
  toolNames: string[];
  instructionMode: string;
}

export interface MuseRuntime {
  serial: number;
  connection: MspConnection;
  sessionId: string | null;
  museHome: string | null;
  serverVersion: string | null;
  sessionLogPath: string | null;
  approvalMode: string;
  modelId: string | null;
  translator: MuseTranslator;
  openTurnIds: Set<string>;
  turnSettledWaiters: Map<string, Array<() => void>>;
  pendingApprovals: Map<string, MspApprovalRequestParams>;
  /**
   * The decision bb already collected for an approval, kept until Muse reports
   * that approval terminal. An approval spans as many stages as the command has
   * unresolved argv fragments, and every one of them needs its own
   * `approval/decide`; re-asking the user per fragment would be bb prompting
   * about a command it has already been answered on.
   */
  approvalDecisions: Map<string, PendingInteractionApprovalDecision>;
  /** Approvals whose stage chain this bridge is already walking. */
  approvalsInFlight: Set<string>;
  pendingUserInputs: Map<string, MspUserInputRequestParams>;
  /**
   * The highest view cursor this runtime has seen, from push or from a page.
   * View cursors are opaque and ascending, so this is the only thing a client
   * needs to ask Muse for everything it has not been handed yet.
   */
  lastViewCursor: string | null;
  /** When the child last said anything at all, for the stall watchdog. */
  lastViewActivityAt: number;
  reconcileTimer: NodeJS.Timeout | null;
  reconciling: boolean;
  /** A dropped stream is worth saying once per runtime, not once per recovery. */
  reportedViewGap: boolean;
  /** Likewise a read bb could not make; the turn keeps running either way. */
  reportedViewReadFailure: boolean;
  /**
   * The highest source sequence bb has folded, from push or from a page. View
   * cursors are opaque and cannot be compared, but every sourced view event
   * carries the source record it came from — which is ordered, and is what
   * makes a re-read from the start of the view safe to run.
   */
  deliveredThroughSequence: number;
  /**
   * Consecutive reads that came back with nothing while a turn was open. One is
   * a slow model call; a long run of them is a session that has stopped.
   */
  quietReconciles: number;
  /**
   * How many turns this runtime has ever opened. A prompt that opens none is a
   * prompt the provider answered without working; anything else is a turn, and
   * whether bb heard about it over push or by reading the view back is not a
   * difference the settlement may depend on.
   */
  turnsOpened: number;
  closing: boolean;
}

/**
 * The prompt whose turn is on the wire, held until that turn settles.
 *
 * Muse fails a turn for conditions bb already knows how to clear — a route its
 * reasoning history cannot survive, an expired login, a child that died — and a
 * client that only records the failure has thrown the user's prompt away. What
 * they type next then lands on the rebuilt session as the prompt, so the answer
 * they get is to the wrong question. bb owns the rerun instead.
 */
export interface InFlightTurn {
  commandId: string;
  /** Named by Muse's reply, which the turn's own terminal can arrive before. */
  providerTurnId: string | null;
  input: readonly PromptInput[];
  options: BridgeExecutionOptions;
  /** A rerun that fails again is a real failure, not another rebuild. */
  reran: boolean;
}

export interface MuseAttachment {
  threadId: string;
  cwd: string;
  construction: SessionConstruction;
  constructionSignature: string;
  dynamicTools: DynamicTool[];
  instructions: string | null;
  /** Delivered on the next turn, then cleared: MSP has no system-prompt slot. */
  pendingInstructions: string | null;
  /**
   * Delivered on the next turn, then cleared: the tail of a conversation a
   * replaced session could not carry, read back out of its own log.
   */
  pendingHandoff: string | null;
  inFlightTurn: InFlightTurn | null;
  providerSessionId: string | null;
  configHome: string | null;
  runtime: MuseRuntime | null;
  identityAnnounced: boolean;
  pendingPreIdentityDeltas: ThreadDelta[];
  /** Set when the next turn must rebuild; `fresh` drops the session's history. */
  restartBeforeNextTurn: { reason: string; fresh: boolean } | null;
  idleTimer: NodeJS.Timeout | null;
  closing: boolean;
}

export function constructionSignature(
  construction: SessionConstruction,
): string {
  return JSON.stringify({
    cwd: construction.cwd,
    approvalMode: construction.approvalMode,
    disableSandbox: construction.posture.disableSandbox,
    sandboxNetwork: construction.posture.sandboxNetwork,
    trustWorkspace: construction.posture.trustWorkspace,
    instructionMode: construction.instructionMode,
    tools: [...construction.toolNames].sort(),
  });
}

export function createRuntime(args: {
  serial: number;
  connection: MspConnection;
  cwd: string;
  approvalMode: string;
}): MuseRuntime {
  return {
    serial: args.serial,
    connection: args.connection,
    sessionId: null,
    museHome: null,
    serverVersion: null,
    sessionLogPath: null,
    approvalMode: args.approvalMode,
    modelId: null,
    translator: new MuseTranslator({ cwd: args.cwd }),
    openTurnIds: new Set(),
    turnSettledWaiters: new Map(),
    pendingApprovals: new Map(),
    approvalDecisions: new Map(),
    approvalsInFlight: new Set(),
    pendingUserInputs: new Map(),
    lastViewCursor: null,
    lastViewActivityAt: Date.now(),
    reconcileTimer: null,
    reconciling: false,
    reportedViewGap: false,
    reportedViewReadFailure: false,
    deliveredThroughSequence: 0,
    quietReconciles: 0,
    turnsOpened: 0,
    closing: false,
  };
}

/**
 * Waits for a turn to reach its terminal, the way an interrupt has to before
 * `thread/stop` answers: after the stop is answered bb detaches the thread, so
 * anything still owed must already be on the wire.
 */
export function waitForTurnSettlement(
  runtime: MuseRuntime,
  turnId: string,
  timeoutMs: number,
): Promise<boolean> {
  if (!runtime.openTurnIds.has(turnId)) {
    return Promise.resolve(true);
  }
  return new Promise<boolean>((resolve) => {
    const onSettled = (): void => {
      clearTimeout(timer);
      resolve(true);
    };
    const timer = setTimeout(() => {
      const waiters = runtime.turnSettledWaiters.get(turnId);
      if (waiters !== undefined) {
        runtime.turnSettledWaiters.set(
          turnId,
          waiters.filter((waiter) => waiter !== onSettled),
        );
      }
      resolve(false);
    }, timeoutMs);
    timer.unref?.();
    const waiters = runtime.turnSettledWaiters.get(turnId) ?? [];
    waiters.push(onSettled);
    runtime.turnSettledWaiters.set(turnId, waiters);
  });
}

/**
 * Tracks turn lifecycle on the way out so an interrupt, a child exit, or a
 * replacement can settle whatever is still open.
 */
export function noteOutboundDeltas(
  runtime: MuseRuntime,
  deltas: readonly ThreadDelta[],
): void {
  for (const delta of deltas) {
    if (delta.kind === "turn.open" && delta.providerTurnId !== undefined) {
      runtime.openTurnIds.add(delta.providerTurnId);
      runtime.turnsOpened += 1;
    }
    if (delta.kind === "turn.boundary" && delta.providerTurnId !== undefined) {
      runtime.openTurnIds.delete(delta.providerTurnId);
      const waiters = runtime.turnSettledWaiters.get(delta.providerTurnId);
      if (waiters !== undefined) {
        runtime.turnSettledWaiters.delete(delta.providerTurnId);
        for (const resolve of waiters) {
          resolve();
        }
      }
    }
  }
}
