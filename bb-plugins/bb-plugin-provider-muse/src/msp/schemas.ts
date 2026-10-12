import { z } from "zod";

/**
 * Narrow decoders for the slice of the Muse Session Protocol this bridge
 * consumes. MSP is additive-optional by contract, so every object stays lenient
 * about unknown members and strict about what the translator reads.
 */

export const MSP_METHODS = {
  initialize: "initialize",
  sessionStart: "session/start",
  sessionResume: "session/resume",
  sessionFork: "session/fork",
  sessionRead: "session/read",
  sessionCompact: "session/compact",
  sessionSetModel: "session/setModel",
  sessionSetApprovalMode: "session/setApprovalMode",
  modelList: "model/list",
  turnStart: "turn/start",
  turnSteer: "turn/steer",
  turnInterrupt: "turn/interrupt",
  viewUnsubscribe: "view/unsubscribe",
  viewPage: "view/page",
  approvalDecide: "approval/decide",
  approvalListPending: "approval/listPending",
  userInputAnswer: "userInput/answer",
  userInputCancel: "userInput/cancel",
  userInputClarify: "userInput/clarify",
} as const;

export const mspTokenUsageSchema = z
  .object({
    inputTokens: z.number(),
    outputTokens: z.number(),
    cachedTokens: z.number(),
    reasoningTokens: z.number(),
    cacheReadTokens: z.number().optional(),
    cacheWriteTokens: z.number().optional(),
  })
  .loose();
export type MspTokenUsage = z.infer<typeof mspTokenUsageSchema>;

export const mspSessionSchema = z
  .object({
    sessionId: z.string().min(1),
    activeTurnId: z.string().nullable(),
    modelId: z.string().nullable(),
    providerId: z.string().nullable(),
    path: z.string(),
    status: z.string(),
    workspaceRoot: z.string().nullable(),
    approvalMode: z
      .object({ mode: z.string(), source: z.string().optional() })
      .loose()
      .optional(),
  })
  .loose();
export type MspSession = z.infer<typeof mspSessionSchema>;

export const mspInitializeResultSchema = z
  .object({
    museHome: z.string(),
    serverInfo: z.object({ name: z.string(), version: z.string() }).loose(),
    schema: z.object({ version: z.number(), fingerprint: z.string() }).loose(),
    grantedCapabilities: z.array(z.string()).default([]),
    experimentalApi: z.boolean().default(false),
    sessionDurability: z.string().optional(),
  })
  .loose();

export const mspSessionStartResultSchema = z
  .object({ session: mspSessionSchema, viewCursor: z.string() })
  .loose();

export const mspSessionResumeResultSchema = z
  .object({ session: mspSessionSchema, viewCursor: z.string() })
  .loose();

/**
 * `session/read` folds a stored session without loading it, so a replacement
 * session can be told what the session it replaced had already said. Only the
 * transcript's speech is read here; the shape stays minimal so a history rung
 * bb does not use can never fail the parse.
 */
const mspHistoryItemSchema = z
  .object({
    kind: z.string(),
    text: z.string().optional(),
    /** `userMessage`: what bb showed the user, without the wrappers bb added. */
    displayText: z.string().optional(),
  })
  .loose();

export const mspSessionReadResultSchema = z
  .object({
    session: mspSessionSchema,
    history: z
      .object({
        mode: z.string(),
        items: z.array(mspHistoryItemSchema).nullable().optional(),
        snapshot: z
          .object({
            state: z
              .object({ items: z.array(mspHistoryItemSchema).optional() })
              .loose(),
          })
          .loose()
          .nullable()
          .optional(),
      })
      .loose(),
  })
  .loose();

export const mspTurnStartResultSchema = z
  .object({
    commandId: z.string(),
    turnId: z.string().min(1),
    disposition: z.string(),
    startedNewTurn: z.boolean().default(false),
  })
  .loose();

export const mspTurnSteerResultSchema = z
  .object({ commandId: z.string(), turnId: z.string().min(1) })
  .loose();

export const mspTurnInterruptResultSchema = z
  .object({ commandId: z.string(), turnId: z.string().min(1) })
  .loose();

export const mspCommandAckSchema = z
  .object({ commandId: z.string(), status: z.string() })
  .loose();

export const mspEmptyResultSchema = z.object({}).loose();

const mspModelCostSchema = z
  .object({
    input: z.string(),
    output: z.string(),
    cached: z.string(),
    currency: z.string().nullable(),
  })
  .loose();

export const mspModelCatalogEntrySchema = z
  .object({
    modelId: z.string().min(1),
    displayLabel: z.string().min(1),
    description: z.string().nullable(),
    contextLimit: z.number().nullable(),
    outputLimit: z.number().nullable(),
    cost: mspModelCostSchema.nullable(),
    providerId: z.string(),
    profileId: z.string().nullable(),
    releaseDate: z.string().nullable(),
    isDefault: z.boolean(),
    isActive: z.boolean(),
  })
  .loose();
export type MspModelCatalogEntry = z.infer<typeof mspModelCatalogEntrySchema>;

export const mspModelListResultSchema = z
  .object({
    models: z.array(z.unknown()),
    providerId: z.string().optional(),
    source: z.string().optional(),
  })
  .loose();

export const mspItemSchema = z
  .object({
    itemId: z.string().min(1),
    kind: z.string(),
    status: z.string(),
    revision: z.number(),
    turnId: z.string().nullable().optional(),
    text: z.string().optional(),
    displayText: z.string().optional(),
    summary: z.array(z.string()).optional(),
    tool: z.string().optional(),
    args: z.string().optional(),
    callId: z.string().optional(),
    visibleOutput: z.string().optional(),
    truncated: z.boolean().optional(),
    exitCode: z.number().optional(),
    exitSignal: z.number().optional(),
    commandText: z.string().optional(),
    durationMs: z.number().optional(),
    failureKind: z.string().optional(),
    failureReason: z.string().optional(),
    fallbackText: z.string().optional(),
    approvalId: z.string().optional(),
    subagentId: z.string().optional(),
    childSessionId: z.string().optional(),
    objective: z.string().optional(),
    role: z.string().optional(),
    depth: z.number().optional(),
    controlStatus: z.string().optional(),
    result: z
      .object({
        summary: z.string(),
        text: z.string().optional(),
        errorKind: z.string().optional(),
      })
      .loose()
      .optional(),
    usage: mspTokenUsageSchema.optional(),
    entryId: z.string().optional(),
    scriptId: z.string().optional(),
    message: z.string().optional(),
    triggerSource: z.string().optional(),
    children: z
      .array(
        z
          .object({
            childId: z.string(),
            attempt: z.number(),
            label: z.string().optional(),
            phase: z.string().optional(),
            status: z.string(),
            terminal: z.string().optional(),
          })
          .loose(),
      )
      .optional(),
    outcome: z.string().optional(),
    reason: z.string().optional(),
    tokensBefore: z.number().optional(),
    tokensAfter: z.number().optional(),
    trigger: z.string().optional(),
  })
  .loose();
export type MspItem = z.infer<typeof mspItemSchema>;

export const mspItemLifecycleParamsSchema = z
  .object({ sessionId: z.string().min(1), item: mspItemSchema })
  .loose();

export const mspItemDeltaParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    itemId: z.string().min(1),
    delta: z.string(),
    field: z.string().optional(),
  })
  .loose();

export const mspTurnStartedParamsSchema = z
  .object({ sessionId: z.string().min(1), turnId: z.string().min(1) })
  .loose();

export const mspTurnCompletedParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    turnId: z.string().min(1),
    terminal: z.string(),
    reason: z.string().optional(),
    usage: mspTokenUsageSchema.optional(),
    error: z
      .object({
        kind: z.string(),
        message: z.string(),
        retryable: z.boolean(),
      })
      .loose()
      .optional(),
  })
  .loose();

export const mspTurnRetryScheduledParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    turnId: z.string().min(1),
    attempt: z.number(),
    maxAttempts: z.number(),
    nextAttempt: z.number(),
    reason: z.string(),
    retryDelayMs: z.number(),
  })
  .loose();

export const mspTurnUnqueuedParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    turnId: z.string().min(1),
    commandId: z.string(),
  })
  .loose();

export const mspTokenUsageParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    turnId: z.string().min(1),
    promptTokens: z.number(),
    totalTokens: z.number(),
    usage: mspTokenUsageSchema,
    cumulative: z
      .object({
        promptTokens: z.number(),
        outputTokens: z.number(),
        totalTokens: z.number(),
      })
      .loose(),
    modelId: z.string().nullable().optional(),
  })
  .loose();

export const mspContextUsageParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    usedTokens: z.number(),
    windowTokens: z.number().optional(),
    pressure: z.string(),
  })
  .loose();

export const mspTodoListChangedParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    revision: z.number(),
    sourceTool: z.string(),
    items: z.array(
      z
        .object({
          text: z.string(),
          status: z.string(),
          activeForm: z.string().optional(),
        })
        .loose(),
    ),
  })
  .loose();

export const mspModelChangedParamsSchema = z
  .object({ sessionId: z.string().min(1), modelId: z.string().min(1) })
  .loose();

export const mspApprovalChoiceSchema = z
  .object({
    choiceId: z.string().min(1),
    decision: z.string(),
    label: z.string(),
    scope: z.string(),
    acceptsFeedback: z.boolean().optional(),
    rulePreview: z.string().optional(),
  })
  .loose();
export type MspApprovalChoice = z.infer<typeof mspApprovalChoiceSchema>;

export const mspApprovalRequirementRefSchema = z
  .object({ approvalId: z.string().min(1), sourceIndex: z.number() })
  .loose();

/**
 * Muse reviews a shell command one argv stage at a time: `grep … | head; psql …`
 * is eight stages, and only the stages its grammar cannot resolve statically
 * come back for a decision. The stage list rides on the subject so the prompt
 * can say how much of the command one answer covers.
 */
export const mspApprovalStageSchema = z
  .object({
    requirementId: mspApprovalRequirementRefSchema.optional(),
    sourcePosition: z.number().optional(),
    totalStages: z.number().optional(),
    argv: z.array(z.string()).optional(),
    resolution: z.object({ kind: z.string() }).loose().optional(),
  })
  .loose();
export type MspApprovalStage = z.infer<typeof mspApprovalStageSchema>;

export const mspApprovalRequestParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    approvalId: z.string().min(1),
    itemId: z.string().min(1),
    turnId: z.string().min(1),
    toolName: z.string(),
    toolCallId: z.string().optional(),
    rawArgs: z.string().optional(),
    judgeEscalated: z.boolean().optional(),
    protectedWrite: z.boolean().optional(),
    currentRequirementId: mspApprovalRequirementRefSchema,
    availableChoices: z.array(mspApprovalChoiceSchema),
    subject: z
      .object({
        kind: z.string(),
        command: z.string().optional(),
        path: z.string().optional(),
        target: z.string().optional(),
        host: z.string().optional(),
        port: z.number().optional(),
        protocol: z.string().optional(),
        access: z.string().optional(),
        toolName: z.string().optional(),
        workspaceRoot: z.string().optional(),
        stages: z.array(mspApprovalStageSchema).optional(),
      })
      .loose(),
  })
  .loose();
export type MspApprovalRequestParams = z.infer<
  typeof mspApprovalRequestParamsSchema
>;

/**
 * `approval/decide` acknowledges one stage. `terminal` is the whole approval's
 * state, not the stage's: false means Muse is still holding the tool call and
 * owes the next requirement. A reply that omits it is read as non-terminal,
 * because the pending list settles the question either way and a client that
 * guesses "done" parks the turn forever.
 */
export const mspApprovalDecideResultSchema = z
  .object({
    commandId: z.string().optional(),
    approvalId: z.string().optional(),
    status: z.string().optional(),
    terminal: z.boolean().nullish(),
  })
  .loose();

/**
 * The pending fold: one full `approval/request` payload per open approval. It
 * is the authority on which requirement an approval is waiting for, so the
 * bridge re-reads it rather than trusting a notification to have arrived.
 */
export const mspApprovalListPendingResultSchema = z
  .object({
    approvals: z.array(z.unknown()).optional(),
    userInputs: z.array(z.unknown()).optional(),
  })
  .loose();

export const mspApprovalResolvedParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    approvalId: z.string().min(1),
    decision: z.string(),
    resolvedBy: z.string(),
  })
  .loose();

export const mspUserInputQuestionSchema = z
  .object({
    id: z.string().min(1),
    header: z.string(),
    question: z.string(),
    options: z.array(
      z
        .object({ label: z.string(), description: z.string().optional() })
        .loose(),
    ),
    selection: z
      .object({
        mode: z.string(),
        minSelections: z.number().optional(),
        maxSelections: z.number().optional(),
      })
      .loose(),
  })
  .loose();

export const mspUserInputRequestParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    userInputId: z.string().min(1),
    turnId: z.string().min(1),
    itemId: z.string().min(1),
    toolName: z.string().optional(),
    questions: z.array(mspUserInputQuestionSchema),
  })
  .loose();
export type MspUserInputRequestParams = z.infer<
  typeof mspUserInputRequestParamsSchema
>;

export const mspUserInputSettledParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    userInputId: z.string().min(1),
    outcome: z.string(),
  })
  .loose();

export const mspViewGapParamsSchema = z
  .object({
    sessionId: z.string().min(1),
    after: z.string(),
    next: z.string(),
  })
  .loose();

/**
 * `view/page` serves the session view from its source, so it answers even where
 * the live push stream has stopped and the materialized projection on disk has
 * been marked unavailable. Each element is an **unframed** view notification —
 * the `{ method, params }` pair push delivery frames — so a page replays
 * straight back through the same translator the live stream feeds.
 *
 * `item/delta` is never replayed: it is ephemeral-sourced. A recovered item
 * therefore arrives as its terminal snapshot, which carries the same text.
 */
export const mspViewPageResultSchema = z
  .object({
    events: z.array(
      z
        .object({ method: z.string().min(1), params: z.unknown() })
        .loose(),
    ),
    /** Null on an exhausted page: there is no cursor after the end. */
    nextCursor: z.string().nullable().optional(),
  })
  .loose();

export const mspErrorSchema = z
  .object({
    code: z.number(),
    message: z.string(),
    data: z
      .object({ kind: z.string().optional(), reason: z.string().optional() })
      .loose()
      .optional(),
  })
  .loose();
export type MspError = z.infer<typeof mspErrorSchema>;
