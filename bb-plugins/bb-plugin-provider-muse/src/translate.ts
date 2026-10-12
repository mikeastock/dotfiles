import {
  ZERO_TOKEN_USAGE,
  addTokenUsage,
  experimental_COMPACTION_PRESENTATION as COMPACTION_PRESENTATION,
  experimental_fileReadPresentation as fileReadPresentation,
  experimental_planStepsPresentation as planStepsPresentation,
  experimental_presentationTitle as presentationTitle,
  experimental_searchPresentation as searchPresentation,
  experimental_toolPresentation as toolPresentation,
  experimental_webFetchPresentation as webFetchPresentation,
  experimental_webSearchPresentation as webSearchPresentation,
  experimental_withTitle as withTitle,
  type DeltaDelegationShape,
  type DeltaItemShape,
  type DeltaPresentation,
  type ThreadDelta,
  type ThreadEventItemStatus,
  type ThreadEventPlanStep,
  type ThreadEventTokenUsageBreakdown,
  type ThreadEventTurnStatus,
} from "@get-bb/plugin-sdk/provider-bridge";
import { museProviderErrorInfo } from "./error-info.js";
import {
  mspContextUsageParamsSchema,
  mspItemDeltaParamsSchema,
  mspItemLifecycleParamsSchema,
  mspTodoListChangedParamsSchema,
  mspTokenUsageParamsSchema,
  mspTurnCompletedParamsSchema,
  mspTurnRetryScheduledParamsSchema,
  mspTurnStartedParamsSchema,
  mspTurnUnqueuedParamsSchema,
  type MspItem,
} from "./msp/schemas.js";
import {
  MUSE_WORKFLOW_EXTENSION_KIND,
  subagentPresentation,
  workflowPresentation,
} from "./vocabulary.js";

const MAX_TOOL_TITLE_LENGTH = 120;

type StreamKind = "agentMessage" | "reasoning";

interface TrackedItem {
  kind: string;
  shape: DeltaItemShape | null;
  presentation: DeltaPresentation | undefined;
  stream: StreamKind | null;
  streamedText: boolean;
  streamedSummaryIndexes: Set<number>;
  turnId: string | null;
}

export interface MuseTranslatorArgs {
  cwd: string;
}

function itemStatus(status: string): ThreadEventItemStatus {
  switch (status) {
    case "inProgress":
      return "pending";
    case "completed":
      return "completed";
    case "cancelled":
      return "interrupted";
    default:
      return "failed";
  }
}

function turnStatus(terminal: string): ThreadEventTurnStatus {
  switch (terminal) {
    case "completed":
      return "completed";
    case "cancelled":
      return "interrupted";
    default:
      return "failed";
  }
}

function planStepStatus(status: string): ThreadEventPlanStep["status"] {
  switch (status) {
    case "completed":
      return "completed";
    case "inProgress":
      return "active";
    case "cancelled":
      return "failed";
    default:
      return "pending";
  }
}

function parseToolArgs(args: string | undefined): Record<string, unknown> {
  if (args === undefined || args === "") {
    return {};
  }
  try {
    const parsed: unknown = JSON.parse(args);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function stringArg(
  args: Record<string, unknown>,
  ...names: readonly string[]
): string | null {
  for (const name of names) {
    const value = args[name];
    if (typeof value === "string" && value.trim() !== "") {
      return value;
    }
  }
  return null;
}

function stringListArg(
  args: Record<string, unknown>,
  ...names: readonly string[]
): string[] | null {
  for (const name of names) {
    const value = args[name];
    if (Array.isArray(value)) {
      const strings = value.filter(
        (entry): entry is string => typeof entry === "string" && entry !== "",
      );
      if (strings.length > 0) {
        return strings;
      }
    }
  }
  return null;
}

function toolMatches(tool: string, ...needles: readonly string[]): boolean {
  const normalized = tool.toLowerCase();
  return needles.some((needle) => normalized.includes(needle));
}

function truncateTitle(text: string): string {
  return text.length <= MAX_TOOL_TITLE_LENGTH
    ? text
    : `${text.slice(0, MAX_TOOL_TITLE_LENGTH - 1)}…`;
}

interface ClassifiedTool {
  shape: DeltaItemShape;
  presentation: DeltaPresentation;
  outputChannel: "command" | "fileChange" | null;
}

/**
 * Muse names its own tools and grows the set between releases, so the shape is
 * derived from what the call actually is rather than from a fixed name table.
 * Anything unrecognized stays a generic tool row with its arguments intact.
 */
export function classifyMuseTool(args: {
  tool: string;
  toolArgs: string | undefined;
  cwd: string;
  result: string | undefined;
  exitCode: number | undefined;
  failed: boolean;
}): ClassifiedTool {
  const parsed = parseToolArgs(args.toolArgs);
  const tool = args.tool;

  if (toolMatches(tool, "bash", "shell", "exec", "terminal", "command")) {
    const command =
      stringArg(parsed, "command", "cmd", "script", "input") ?? tool;
    return {
      shape: {
        type: "command",
        command,
        cwd: stringArg(parsed, "cwd", "workdir", "directory") ?? args.cwd,
        ...(args.result === undefined ? {} : { aggregatedOutput: args.result }),
        ...(args.exitCode === undefined ? {} : { exitCode: args.exitCode }),
      },
      presentation: withTitle(
        {
          label: { pending: "Running", completed: "Ran" },
          icon: { glyph: "Terminal" },
        },
        presentationTitle(command),
      ),
      outputChannel: "command",
    };
  }

  if (toolMatches(tool, "web_search", "websearch", "search_web")) {
    const queries =
      stringListArg(parsed, "queries") ??
      (stringArg(parsed, "query", "q") === null
        ? null
        : [stringArg(parsed, "query", "q") as string]);
    if (queries !== null) {
      return {
        shape: { type: "webSearch", queries },
        presentation: webSearchPresentation(queries[0]),
        outputChannel: null,
      };
    }
  }

  if (toolMatches(tool, "web_fetch", "webfetch", "fetch_url", "browser_open")) {
    const url = stringArg(parsed, "url", "uri", "target");
    if (url !== null) {
      return {
        shape: {
          type: "webFetch",
          url,
          prompt: stringArg(parsed, "prompt", "question"),
          pattern: stringArg(parsed, "pattern"),
        },
        presentation: webFetchPresentation(url),
        outputChannel: null,
      };
    }
  }

  if (toolMatches(tool, "grep", "search", "glob", "find", "list_dir", "ls")) {
    const query = stringArg(parsed, "pattern", "query", "regex", "glob");
    const path = stringArg(parsed, "path", "dir", "directory", "root");
    const mode = toolMatches(tool, "glob", "find", "list_dir", "ls")
      ? toolMatches(tool, "list_dir", "ls")
        ? "list"
        : "path"
      : "content";
    if (query !== null || path !== null) {
      return {
        shape: {
          type: "search",
          mode,
          query: query ?? path ?? tool,
          ...(path === null ? {} : { path }),
        },
        presentation: searchPresentation({
          mode: mode === "list" ? "path" : mode,
          query: query ?? path ?? tool,
        }),
        outputChannel: null,
      };
    }
  }

  if (toolMatches(tool, "read", "view", "cat", "open_file")) {
    const path = stringArg(parsed, "path", "file", "file_path", "filename");
    if (path !== null) {
      return {
        shape: { type: "fileRead", path },
        presentation: fileReadPresentation(path),
        outputChannel: null,
      };
    }
  }

  if (toolMatches(tool, "write", "edit", "patch", "apply", "create_file")) {
    const path = stringArg(parsed, "path", "file", "file_path", "filename");
    if (path !== null) {
      const kind = toolMatches(tool, "create_file")
        ? "add"
        : toolMatches(tool, "delete", "remove")
          ? "delete"
          : "update";
      return {
        shape: {
          type: "fileChange",
          changes: [
            {
              path,
              kind,
              ...(stringArg(parsed, "diff", "patch") === null
                ? {}
                : { diff: stringArg(parsed, "diff", "patch") as string }),
            },
          ],
        },
        presentation: withTitle(
          {
            label: { pending: "Editing", completed: "Edited" },
            icon: { glyph: "FilePenLine" },
          },
          presentationTitle(path),
        ),
        outputChannel: "fileChange",
      };
    }
  }

  const title = stringArg(parsed, "description", "objective", "query", "path");
  return {
    shape: {
      type: "tool",
      tool,
      args: parsed,
      ...(args.failed
        ? { error: args.result ?? "Tool call failed" }
        : args.result === undefined
          ? {}
          : { result: args.result }),
    },
    presentation:
      title === null
        ? toolPresentation(tool)
        : withTitle(toolPresentation(tool), presentationTitle(truncateTitle(title))),
    outputChannel: null,
  };
}

function delegationShape(item: MspItem): DeltaDelegationShape {
  const summary = item.result?.summary;
  return {
    type: "delegation",
    childRef: item.subagentId ?? item.itemId,
    label: item.objective ?? item.role ?? "Muse subagent",
    background: false,
    ...(summary === undefined ? {} : { summary }),
  };
}

function workflowShape(item: MspItem): DeltaItemShape {
  return {
    type: "extension",
    kind: MUSE_WORKFLOW_EXTENSION_KIND,
    payload: {
      entryId: item.entryId ?? null,
      scriptId: item.scriptId ?? null,
      message: item.message ?? null,
      triggerSource: item.triggerSource ?? null,
      children: (item.children ?? []).map((child) => ({
        childId: child.childId,
        attempt: child.attempt,
        label: child.label ?? null,
        phase: child.phase ?? null,
        status: child.status,
        terminal: child.terminal ?? null,
      })),
    },
  };
}

/**
 * Folds one Muse session's MSP view stream into bb's delta grammar. One
 * instance per provider session: `session.reset` is the id-space boundary, so a
 * replaced session gets a fresh translator.
 */
export class MuseTranslator {
  private readonly cwd: string;
  private readonly items = new Map<string, TrackedItem>();
  private readonly openTurnIds = new Set<string>();
  private usageTotal: ThreadEventTokenUsageBreakdown = ZERO_TOKEN_USAGE;
  private contextWindowTokens: number | null = null;

  constructor(args: MuseTranslatorArgs) {
    this.cwd = args.cwd;
  }

  get openTurns(): readonly string[] {
    return [...this.openTurnIds];
  }

  hasOpenTurn(turnId: string): boolean {
    return this.openTurnIds.has(turnId);
  }

  /**
   * Adopts a turn the bridge opened on Muse's `turn/start` reply rather than on
   * a view notification. The fold has to know about it or `settleOpenTurns`
   * cannot close it, and the `turn/started` that normally follows would open it
   * a second time.
   */
  adoptOpenTurn(turnId: string): ThreadDelta[] {
    if (this.openTurnIds.has(turnId)) {
      return [];
    }
    this.openTurnIds.add(turnId);
    return [{ kind: "turn.open", providerTurnId: turnId }];
  }

  settleOpenTurns(status: ThreadEventTurnStatus, message: string): ThreadDelta[] {
    const deltas: ThreadDelta[] = [];
    for (const turnId of this.openTurnIds) {
      deltas.push({
        kind: "turn.boundary",
        status,
        providerTurnId: turnId,
        ...(status === "failed" ? { error: { message } } : {}),
      });
    }
    this.openTurnIds.clear();
    return deltas;
  }

  onNotification(method: string, params: unknown): ThreadDelta[] {
    switch (method) {
      case "turn/started":
        return this.onTurnStarted(params);
      case "turn/completed":
        return this.onTurnCompleted(params);
      case "turn/retryScheduled":
        return this.onTurnRetryScheduled(params);
      case "turn/unqueued":
      case "turn/retracted":
        return this.onTurnAbandoned(params);
      case "item/started":
        return this.onItemStarted(params);
      case "item/updated":
        return this.onItemUpdated(params);
      case "item/completed":
        return this.onItemCompleted(params);
      case "item/delta":
        return this.onItemDelta(params);
      case "session/tokenUsage":
        return this.onTokenUsage(params);
      case "session/contextUsage":
        return this.onContextUsage(params);
      case "session/todoListChanged":
        return this.onTodoListChanged(params);
      /**
       * `view/gap` is answered by the bridge, not folded here: the dropped
       * range is read back with `view/page` and replayed through this
       * translator, so it arrives as the notifications it always was.
       */
      default:
        return [];
    }
  }

  private onTurnStarted(params: unknown): ThreadDelta[] {
    const parsed = mspTurnStartedParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    if (this.openTurnIds.has(parsed.data.turnId)) {
      return [];
    }
    this.openTurnIds.add(parsed.data.turnId);
    return [{ kind: "turn.open", providerTurnId: parsed.data.turnId }];
  }

  private onTurnCompleted(params: unknown): ThreadDelta[] {
    const parsed = mspTurnCompletedParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const { turnId, terminal, error } = parsed.data;
    const known = this.openTurnIds.delete(turnId);
    const status = turnStatus(terminal);
    const boundaryMessage =
      error?.message ??
      (status === "failed" ? parsed.data.reason : undefined);
    const message = error?.message ?? parsed.data.reason;
    const deltas: ThreadDelta[] = [];

    /**
     * The typed failure, ahead of the boundary that settles the turn. bb's own
     * recovery reads the category off this delta — a turn that fails with only
     * a message is a turn nothing downstream can act on.
     */
    if (status === "failed" && message !== undefined) {
      const errorInfo = museProviderErrorInfo({
        ...(error?.kind === undefined ? {} : { kind: error.kind }),
        message,
      });
      deltas.push({
        kind: "provider.error",
        message: "Muse turn failed",
        detail: message,
        settlesTurn: false,
        willRetry: false,
        ...(errorInfo === null ? {} : { errorInfo, category: errorInfo.category }),
        ...(known ? { providerTurnId: turnId } : { threadScoped: true }),
      });
    }

    deltas.push({
      kind: "turn.boundary",
      status,
      ...(known ? { providerTurnId: turnId } : { claimIfIdle: true }),
      ...(boundaryMessage === undefined
        ? {}
        : { error: { message: boundaryMessage } }),
    });
    return deltas;
  }

  private onTurnRetryScheduled(params: unknown): ThreadDelta[] {
    const parsed = mspTurnRetryScheduledParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const { attempt, maxAttempts, reason, retryDelayMs, turnId } = parsed.data;
    const errorInfo = museProviderErrorInfo({ message: reason });
    return [
      {
        kind: "provider.error",
        message: `Muse model attempt ${attempt}/${maxAttempts} failed: ${reason}`,
        detail: `Retrying in ${Math.round(retryDelayMs / 100) / 10}s`,
        willRetry: true,
        settlesTurn: false,
        ...(errorInfo === null
          ? {}
          : { errorInfo, category: errorInfo.category }),
        ...(this.openTurnIds.has(turnId) ? { providerTurnId: turnId } : {}),
      },
    ];
  }

  private onTurnAbandoned(params: unknown): ThreadDelta[] {
    const parsed = mspTurnUnqueuedParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const known = this.openTurnIds.delete(parsed.data.turnId);
    return [
      {
        kind: "turn.boundary",
        status: "interrupted",
        ...(known
          ? { providerTurnId: parsed.data.turnId }
          : { claimIfIdle: true }),
      },
    ];
  }

  private track(item: MspItem): TrackedItem {
    const existing = this.items.get(item.itemId);
    if (existing !== undefined) {
      return existing;
    }
    const tracked: TrackedItem = {
      kind: item.kind,
      shape: null,
      presentation: undefined,
      stream:
        item.kind === "agentMessage"
          ? "agentMessage"
          : item.kind === "reasoning"
            ? "reasoning"
            : null,
      streamedText: false,
      streamedSummaryIndexes: new Set(),
      turnId: item.turnId ?? null,
    };
    this.items.set(item.itemId, tracked);
    return tracked;
  }

  private turnScope(item: MspItem): { providerTurnId?: string } {
    return this.scopeForTurn(item.turnId ?? null);
  }

  /**
   * Every delta bb's assembler keeps has to name the turn it belongs to. An
   * unscoped `item.*Delta` is discarded outright — the assembler has no open
   * turn to hang it on — so a stream that arrives without this reads as an
   * agent that produced nothing until its terminal snapshot lands. `item/delta`
   * carries no `turnId` of its own, so the turn comes off the item the delta
   * appends to, which `track` recorded when the item opened.
   */
  private scopeForTurn(turnId: string | null): { providerTurnId?: string } {
    return turnId !== null && this.openTurnIds.has(turnId)
      ? { providerTurnId: turnId }
      : {};
  }

  private onItemStarted(params: unknown): ThreadDelta[] {
    const parsed = mspItemLifecycleParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const item = parsed.data.item;
    const tracked = this.track(item);

    switch (item.kind) {
      case "agentMessage":
      case "reasoning":
      case "userMessage":
        return [];
      case "toolCall": {
        const classified = classifyMuseTool({
          tool: item.tool ?? "tool",
          toolArgs: item.args,
          cwd: this.cwd,
          result: undefined,
          exitCode: undefined,
          failed: false,
        });
        tracked.shape = classified.shape;
        tracked.presentation = classified.presentation;
        return [
          {
            kind: "item.open",
            key: { providerItemId: item.itemId },
            item: classified.shape,
            presentation: classified.presentation,
            ...this.turnScope(item),
          },
        ];
      }
      case "userShell": {
        const shape: DeltaItemShape = {
          type: "command",
          command: item.commandText ?? "",
          cwd: this.cwd,
        };
        tracked.shape = shape;
        tracked.presentation = withTitle(
          {
            label: { pending: "Running", completed: "Ran" },
            icon: { glyph: "Terminal" },
          },
          presentationTitle(item.commandText ?? ""),
        );
        return [
          {
            kind: "item.open",
            key: { providerItemId: item.itemId },
            item: shape,
            presentation: tracked.presentation,
            attach: "currentOrLast",
          },
        ];
      }
      case "subagent": {
        const shape = delegationShape(item);
        tracked.shape = shape;
        tracked.presentation = subagentPresentation(
          item.objective ?? "Muse subagent",
        );
        return [
          {
            kind: "item.open",
            key: { providerItemId: item.itemId },
            item: shape,
            presentation: tracked.presentation,
            ...this.turnScope(item),
          },
        ];
      }
      case "workflow": {
        const shape = workflowShape(item);
        tracked.shape = shape;
        tracked.presentation = workflowPresentation(
          item.scriptId ?? item.entryId ?? "Muse workflow",
        );
        return [
          {
            kind: "item.open",
            key: { providerItemId: item.itemId },
            item: shape,
            presentation: tracked.presentation,
            ...this.turnScope(item),
          },
        ];
      }
      default:
        return [];
    }
  }

  private onItemUpdated(params: unknown): ThreadDelta[] {
    const parsed = mspItemLifecycleParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const item = parsed.data.item;
    if (item.kind !== "subagent") {
      return [];
    }
    this.track(item);
    return [
      {
        kind: "item.progress",
        key: { providerItemId: item.itemId },
        snapshot: delegationShape(item),
        ...(item.controlStatus === undefined
          ? {}
          : { message: item.controlStatus }),
        ...this.turnScope(item),
      },
    ];
  }

  private onItemDelta(params: unknown): ThreadDelta[] {
    const parsed = mspItemDeltaParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const { itemId, delta, field } = parsed.data;
    const tracked = this.items.get(itemId);
    if (tracked === undefined || delta === "") {
      return [];
    }
    const path = field ?? "text";
    const scope = this.scopeForTurn(tracked.turnId);

    if (tracked.stream === "agentMessage") {
      tracked.streamedText = true;
      return [
        {
          kind: "item.textDelta",
          key: { providerItemId: itemId },
          channel: "agentMessage",
          text: delta,
          ...scope,
        },
      ];
    }

    if (tracked.stream === "reasoning") {
      const summaryIndex = path.startsWith("summary.")
        ? Number.parseInt(path.slice("summary.".length), 10)
        : null;
      if (summaryIndex !== null && Number.isInteger(summaryIndex)) {
        tracked.streamedSummaryIndexes.add(summaryIndex);
        return [
          {
            kind: "item.textDelta",
            key: { providerItemId: itemId, channel: `summary-${summaryIndex}` },
            channel: "reasoningSummary",
            text: delta,
            ...scope,
          },
        ];
      }
      tracked.streamedText = true;
      return [
        {
          kind: "item.textDelta",
          key: { providerItemId: itemId },
          channel: "reasoningText",
          text: delta,
          ...scope,
        },
      ];
    }

    if (path === "output" && tracked.shape !== null) {
      if (tracked.shape.type === "command") {
        return [
          {
            kind: "item.outputDelta",
            key: { providerItemId: itemId },
            channel: "command",
            text: delta,
            ...scope,
          },
        ];
      }
      if (tracked.shape.type === "fileChange") {
        return [
          {
            kind: "item.outputDelta",
            key: { providerItemId: itemId },
            channel: "fileChange",
            text: delta,
            ...scope,
          },
        ];
      }
    }

    return [];
  }

  private onItemCompleted(params: unknown): ThreadDelta[] {
    const parsed = mspItemLifecycleParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const item = parsed.data.item;
    const tracked = this.track(item);
    const status = itemStatus(item.status);
    const scope = this.turnScope(item);

    switch (item.kind) {
      case "userMessage":
        this.items.delete(item.itemId);
        return [];

      case "agentMessage": {
        this.items.delete(item.itemId);
        const text = item.text ?? "";
        if (!tracked.streamedText && text.trim() === "") {
          return [];
        }
        return [
          {
            kind: "item.textClose",
            key: { providerItemId: item.itemId },
            channel: "agentMessage",
            text,
            ...scope,
          },
        ];
      }

      case "reasoning": {
        this.items.delete(item.itemId);
        const deltas: ThreadDelta[] = [];
        const summary = item.summary ?? [];
        summary.forEach((part, index) => {
          if (part.trim() === "" && !tracked.streamedSummaryIndexes.has(index)) {
            return;
          }
          deltas.push({
            kind: "item.textClose",
            key: { providerItemId: item.itemId, channel: `summary-${index}` },
            channel: "reasoningSummary",
            text: part,
            ...scope,
          });
        });
        const text = item.text ?? "";
        if (tracked.streamedText || text.trim() !== "") {
          deltas.push({
            kind: "item.textClose",
            key: { providerItemId: item.itemId },
            channel: "reasoningText",
            text,
            ...scope,
          });
        }
        return deltas;
      }

      case "toolCall": {
        this.items.delete(item.itemId);
        const failed = status === "failed";
        const result =
          item.visibleOutput ?? item.failureReason ?? item.fallbackText;
        const classified = classifyMuseTool({
          tool: item.tool ?? "tool",
          toolArgs: item.args,
          cwd: this.cwd,
          result,
          exitCode: item.exitCode,
          failed,
        });
        return [
          {
            kind: "item.close",
            key: { providerItemId: item.itemId },
            status,
            item: classified.shape,
            presentation: classified.presentation,
            ...(result === undefined ? {} : { resultText: result }),
            ...(classified.outputChannel === "command" && result !== undefined
              ? { aggregatedOutput: result }
              : {}),
            ...(item.exitCode === undefined ? {} : { exitCode: item.exitCode }),
            ...scope,
          },
        ];
      }

      case "userShell": {
        this.items.delete(item.itemId);
        const output = item.visibleOutput ?? "";
        return [
          {
            kind: "item.close",
            key: { providerItemId: item.itemId },
            status,
            item: {
              type: "command",
              command: item.commandText ?? "",
              cwd: this.cwd,
              aggregatedOutput: output,
              ...(item.exitCode === undefined ? {} : { exitCode: item.exitCode }),
              ...(item.durationMs === undefined
                ? {}
                : { durationMs: item.durationMs }),
            },
            presentation:
              tracked.presentation ??
              withTitle(
                {
                  label: { pending: "Running", completed: "Ran" },
                  icon: { glyph: "Terminal" },
                },
                presentationTitle(item.commandText ?? ""),
              ),
            aggregatedOutput: output,
            ...(item.exitCode === undefined ? {} : { exitCode: item.exitCode }),
          },
        ];
      }

      case "subagent": {
        this.items.delete(item.itemId);
        return [
          {
            kind: "item.close",
            key: { providerItemId: item.itemId },
            status,
            item: delegationShape(item),
            presentation:
              tracked.presentation ??
              subagentPresentation(item.objective ?? "Muse subagent"),
            ...(item.result?.text === undefined
              ? {}
              : { resultText: item.result.text }),
            ...scope,
          },
        ];
      }

      case "workflow": {
        this.items.delete(item.itemId);
        return [
          {
            kind: "item.close",
            key: { providerItemId: item.itemId },
            status,
            item: workflowShape(item),
            presentation:
              tracked.presentation ??
              workflowPresentation(item.scriptId ?? "Muse workflow"),
            ...scope,
          },
        ];
      }

      case "compaction": {
        this.items.delete(item.itemId);
        if (item.outcome !== undefined && item.outcome !== "compacted") {
          return [];
        }
        return [
          {
            kind: "item.close",
            key: { providerItemId: item.itemId },
            status,
            item: { type: "compaction" },
            presentation: COMPACTION_PRESENTATION,
            ...scope,
          },
          { kind: "context.compacted", ...scope },
        ];
      }

      default:
        this.items.delete(item.itemId);
        return [];
    }
  }

  private onTokenUsage(params: unknown): ThreadDelta[] {
    const parsed = mspTokenUsageParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const { usage, promptTokens, totalTokens, turnId } = parsed.data;
    const last: ThreadEventTokenUsageBreakdown = {
      totalTokens,
      inputTokens: promptTokens,
      cachedInputTokens: usage.cacheReadTokens ?? usage.cachedTokens,
      outputTokens: usage.outputTokens,
      reasoningOutputTokens: usage.reasoningTokens,
    };
    this.usageTotal = addTokenUsage(this.usageTotal, last);
    return [
      {
        kind: "usage",
        total: this.usageTotal,
        last,
        modelContextWindow: this.contextWindowTokens,
        ...(this.openTurnIds.has(turnId) ? { providerTurnId: turnId } : {}),
      },
    ];
  }

  private onContextUsage(params: unknown): ThreadDelta[] {
    const parsed = mspContextUsageParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const { usedTokens, windowTokens } = parsed.data;
    if (windowTokens !== undefined) {
      this.contextWindowTokens = windowTokens;
    }
    return [
      {
        kind: "contextWindow",
        used: usedTokens,
        size: this.contextWindowTokens,
        estimated: false,
        attach: "currentOrLast",
      },
    ];
  }

  private onTodoListChanged(params: unknown): ThreadDelta[] {
    const parsed = mspTodoListChangedParamsSchema.safeParse(params);
    if (!parsed.success) {
      return [];
    }
    const steps: ThreadEventPlanStep[] = parsed.data.items.map((entry) => ({
      step: entry.text,
      status: planStepStatus(entry.status),
    }));
    if (steps.length === 0) {
      return [];
    }
    const key = { providerItemId: `todo-${parsed.data.revision}` };
    const shape: DeltaItemShape = { type: "planSteps", steps };
    const presentation = planStepsPresentation(steps);
    return [
      { kind: "item.open", key, item: shape, presentation },
      { kind: "item.close", key, status: "completed", item: shape, presentation },
    ];
  }


}
