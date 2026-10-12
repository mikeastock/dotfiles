import type {
  ProviderErrorCategory,
  ProviderErrorInfo,
} from "@get-bb/plugin-sdk/provider-bridge";

/**
 * bb's own recovery runs on the error *category*, not on the message: core
 * raises `turn.failed` carrying `errorInfo`, and the provider-retry plugin
 * decides from it whether a turn earns a scheduled re-attempt. A bridge that
 * reports only prose is a bridge whose threads never get that — which is the
 * difference between a muse thread and a codex or claude-code one.
 *
 * Codex and Claude Code classify from structured provider fields. MSP gives a
 * turn failure an open `kind` and a human message and nothing else — there is
 * no status code and no rate-limit window on the wire — so the kind decides
 * what it can and narrow message patterns decide the rest. Nothing is inferred
 * from a number found loose in prose: an unrecognised failure stays `unknown`
 * rather than being dressed up as something bb would act on.
 */

const AUTH_PATTERN =
  /\b(?:40[13]|unauthori[sz]ed|authentication failed|oauth|not authenticated|sign[- ]?in|invalid api key|expired token)\b/i;
const BILLING_PATTERN =
  /\b(?:402|billing|payment required|insufficient (?:credit|funds|balance))\b/i;
const RATE_LIMIT_PATTERN =
  /\b(?:429|rate[-\s]?limit(?:ed)?|quota|usage limit|too many requests|resets_at)\b/i;
const OVERLOADED_PATTERN =
  /\b(?:529|503|overloaded|over capacity|at capacity|temporarily unavailable|server is busy)\b/i;
const CONTEXT_WINDOW_PATTERN =
  /context (?:window|length) (?:exceeded|too long)|maximum context|prompt is too long|too many tokens/i;
const CONNECTION_PATTERN =
  /\b(?:ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|EAI_AGAIN)\b|connection (?:failed|refused|reset|closed)|network (?:error|unreachable)|dns (?:error|failure)|failed to connect/i;
const STREAM_PATTERN =
  /stream (?:disconnected|closed|ended|interrupted)|incomplete chunked|unexpected end of stream/i;
const INTERNAL_PATTERN =
  /\b(?:500|502|504)\b|internal server error|bad gateway|gateway timeout/i;
const BAD_REQUEST_PATTERN =
  /\b400\b|invalid request|unsupported (?:model|parameter)|unknown model/i;

/**
 * Only a status the message names as one. `429` beside the word `status` or
 * `HTTP` is a status code; a bare three-digit run inside prose is not.
 */
const EXPLICIT_STATUS_PATTERN =
  /(?:\bhttp\b[^0-9]{0,12}|\bstatus(?:\s+code)?\b[^0-9]{0,4})(?<status>[45]\d{2})\b/i;

function categoryFromMessage(message: string): ProviderErrorCategory | null {
  if (AUTH_PATTERN.test(message)) {
    return "unauthorized";
  }
  if (BILLING_PATTERN.test(message)) {
    return "billing";
  }
  if (RATE_LIMIT_PATTERN.test(message)) {
    return "rate-limit";
  }
  if (OVERLOADED_PATTERN.test(message)) {
    return "overloaded";
  }
  if (CONTEXT_WINDOW_PATTERN.test(message)) {
    return "context-window-exceeded";
  }
  if (CONNECTION_PATTERN.test(message)) {
    return "connection-failed";
  }
  if (STREAM_PATTERN.test(message)) {
    return "stream-disconnected";
  }
  if (INTERNAL_PATTERN.test(message)) {
    return "internal";
  }
  if (BAD_REQUEST_PATTERN.test(message)) {
    return "bad-request";
  }
  return null;
}

/**
 * MSP's `TurnErrorKind` is an open enum of the runtime's own terminal failure
 * classes (tdd SS4.5.1). Everything but `modelError` names a fault in the host
 * rather than in the model call, so the kind alone settles it.
 */
function categoryFromKind(kind: string): ProviderErrorCategory | null {
  switch (kind) {
    case "stepLimit":
      return "max-turns";
    case "configError":
      return "bad-request";
    case "logError":
    case "projectionError":
    case "environmentError":
    case "launchError":
    case "workflowLaunchError":
      return "internal";
    default:
      return null;
  }
}

export function museProviderErrorInfo(args: {
  kind?: string | undefined;
  message: string;
}): ProviderErrorInfo | null {
  const message = args.message.trim();
  const providerCode = args.kind ?? null;
  const category =
    categoryFromMessage(message) ??
    (providerCode === null ? null : categoryFromKind(providerCode)) ??
    "unknown";
  const status = EXPLICIT_STATUS_PATTERN.exec(message)?.groups?.status;
  const httpStatusCode = status === undefined ? null : Number(status);

  /** Nothing to say beyond the prose bb already has. */
  if (category === "unknown" && providerCode === null && httpStatusCode === null) {
    return null;
  }
  return { category, providerCode, httpStatusCode };
}
