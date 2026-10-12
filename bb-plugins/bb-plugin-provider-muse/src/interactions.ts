import {
  USER_QUESTION_MAX_OPTIONS,
  USER_QUESTION_MAX_QUESTIONS,
  experimental_toolPresentation as toolPresentation,
  type ApprovalPendingInteractionPayload,
  type PendingInteractionApprovalDecision,
  type PendingInteractionResolution,
  type UserQuestionPendingInteractionPayload,
} from "@get-bb/plugin-sdk/provider-bridge";
import type {
  MspApprovalChoice,
  MspApprovalRequestParams,
  MspUserInputRequestParams,
} from "./msp/schemas.js";

/**
 * MSP mints the choices an approval will accept and guards the decision with a
 * requirement id, so the bridge maps bb's three decisions onto whichever
 * choices this stage actually offers rather than assuming a fixed set.
 */
function decisionForChoice(
  choice: MspApprovalChoice,
): PendingInteractionApprovalDecision | null {
  if (choice.decision.startsWith("denied") || choice.decision === "abort") {
    return "deny";
  }
  if (!choice.decision.startsWith("approved")) {
    return null;
  }
  return choice.scope === "once" ? "allow_once" : "allow_for_session";
}

export function approvalDecisionsFromChoices(
  choices: readonly MspApprovalChoice[],
): PendingInteractionApprovalDecision[] {
  const decisions = new Set<PendingInteractionApprovalDecision>();
  for (const choice of choices) {
    const decision = decisionForChoice(choice);
    if (decision !== null) {
      decisions.add(decision);
    }
  }
  return [...decisions];
}

export function chooseApprovalChoiceId(
  choices: readonly MspApprovalChoice[],
  decision: PendingInteractionApprovalDecision,
): string | null {
  const exact = choices.find(
    (choice) => decisionForChoice(choice) === decision,
  );
  if (exact !== undefined) {
    return exact.choiceId;
  }
  if (decision === "allow_for_session") {
    const once = choices.find(
      (choice) => decisionForChoice(choice) === "allow_once",
    );
    return once?.choiceId ?? null;
  }
  return null;
}

/**
 * Muse decomposes a shell command into argv stages and reviews the ones its
 * grammar cannot resolve — a `${VAR}` expansion, a substitution, a heredoc —
 * even under `allowAll`. bb asks about the command, not the fragment, so a
 * decision carries across every remaining stage of the same approval; the
 * count is stated because the answer covers more than the argv on screen.
 */
export function unresolvedApprovalStages(
  params: MspApprovalRequestParams,
): number {
  const stages = params.subject.stages;
  if (stages === undefined) {
    return 0;
  }
  return stages.filter((stage) => stage.resolution?.kind === "unresolved")
    .length;
}

function approvalReason(params: MspApprovalRequestParams): string | null {
  const reasons: string[] = [];
  if (params.judgeEscalated === true) {
    reasons.push("Muse's approval judge escalated this call for review.");
  }
  if (params.protectedWrite === true) {
    reasons.push("This write targets a protected path.");
  }
  const unresolved = unresolvedApprovalStages(params);
  if (unresolved > 1) {
    reasons.push(
      `Muse reviews this command in ${String(unresolved)} stages; your answer covers all of them.`,
    );
  }
  return reasons.length === 0 ? null : reasons.join(" ");
}

export function approvalPayloadFromMsp(
  params: MspApprovalRequestParams,
): ApprovalPendingInteractionPayload | null {
  const availableDecisions = approvalDecisionsFromChoices(
    params.availableChoices,
  );
  if (availableDecisions.length === 0) {
    return null;
  }
  const reason = approvalReason(params);
  const subject = params.subject;

  if (subject.kind === "shell" && subject.command !== undefined) {
    return {
      kind: "approval",
      subject: {
        kind: "command",
        itemId: params.itemId,
        command: subject.command,
        cwd: subject.workspaceRoot ?? null,
        actions: [],
        sessionGrant: null,
      },
      reason,
      availableDecisions,
    };
  }

  if (subject.kind === "fileAccess" && subject.path !== undefined) {
    return {
      kind: "approval",
      subject: {
        kind: "file_change",
        itemId: params.itemId,
        writeScope: subject.path,
        sessionGrant: null,
      },
      reason,
      availableDecisions,
    };
  }

  const toolName = subject.toolName ?? params.toolName;
  const detail =
    subject.kind === "network"
      ? [subject.protocol, subject.host, subject.port]
          .filter((part) => part !== undefined && part !== "")
          .join(" ")
      : (subject.target ?? subject.command ?? subject.path ?? "");
  const presentation = toolPresentation(toolName);
  return {
    kind: "approval",
    subject: {
      kind: "tool_use",
      itemId: params.itemId,
      tool: toolName,
      presentation:
        detail === ""
          ? presentation
          : { ...presentation, detail: detail.slice(0, 280) },
    },
    reason,
    availableDecisions,
  };
}

export function userQuestionPayloadFromMsp(
  params: MspUserInputRequestParams,
): UserQuestionPendingInteractionPayload | null {
  const questions = params.questions
    .slice(0, USER_QUESTION_MAX_QUESTIONS)
    .map((question) => {
      const options = question.options
        .slice(0, USER_QUESTION_MAX_OPTIONS)
        .map((option) => ({
          value: option.label,
          label: option.label,
          ...(option.description === undefined
            ? {}
            : { description: option.description }),
        }));
      return {
        id: question.id,
        prompt: question.question,
        ...(question.header === "" ? {} : { shortLabel: question.header }),
        multiSelect: question.selection.mode === "multiple",
        ...(options.length === 0 ? {} : { options }),
        allowFreeText: true,
      };
    });
  if (questions.length === 0) {
    return null;
  }
  return { kind: "user_question", questions };
}

export interface MuseUserInputSettlement {
  method: "userInput/answer" | "userInput/clarify" | "userInput/cancel";
  answers?: {
    questionId: string;
    selectedLabel?: string;
    selectedLabels?: string[];
    freeText?: string;
  }[];
  clarification?: { format: "text"; content: string };
  reason?: string;
}

const MUSE_FREE_TEXT_MAX = 500;

/**
 * bb answers every question with a selection, free text, or both. MSP accepts
 * exactly one of those per answer, so a free-text-only reply becomes a
 * clarification and a mixed reply keeps the selection — the model re-decides on
 * the clarification either way.
 */
export function userInputSettlementFromResolution(
  params: MspUserInputRequestParams,
  resolution: PendingInteractionResolution,
): MuseUserInputSettlement {
  if (!("kind" in resolution) || resolution.kind !== "user_answer") {
    return { method: "userInput/cancel", reason: "bb declined the prompt" };
  }

  const answers: NonNullable<MuseUserInputSettlement["answers"]> = [];
  const freeTexts: string[] = [];

  for (const question of params.questions) {
    const answer = resolution.answers[question.id];
    if (answer === undefined) {
      continue;
    }
    if (answer.freeText !== undefined && answer.selected.length === 0) {
      freeTexts.push(answer.freeText);
      continue;
    }
    if (answer.selected.length === 0) {
      continue;
    }
    if (answer.freeText !== undefined) {
      freeTexts.push(answer.freeText);
    }
    answers.push(
      question.selection.mode === "multiple"
        ? { questionId: question.id, selectedLabels: answer.selected }
        : { questionId: question.id, selectedLabel: answer.selected[0] },
    );
  }

  if (answers.length === params.questions.length && freeTexts.length === 0) {
    return { method: "userInput/answer", answers };
  }
  if (freeTexts.length > 0) {
    return {
      method: "userInput/clarify",
      clarification: {
        format: "text",
        content: freeTexts.join("\n\n").slice(0, MUSE_FREE_TEXT_MAX),
      },
    };
  }
  return { method: "userInput/cancel", reason: "bb answered no questions" };
}
