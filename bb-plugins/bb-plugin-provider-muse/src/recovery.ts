import type { ProviderRecoveryHint } from "@get-bb/plugin-sdk/provider-bridge";
import { mspTurnCompletedParamsSchema } from "./msp/schemas.js";

/**
 * MSP types a turn failure only as broadly as `modelError`, so the condition a
 * client must act on lives in the message. The first-party bridges match text
 * here too — codex keeps regexes for its auth and rate-limit wording — because
 * the alternative is treating an expired login as an ordinary failure. The
 * matches stay narrow and drive a typed hint, never a fabricated result.
 */

const AUTH_PATTERN =
  /\b(?:40[13]|unauthori[sz]ed|authentication failed|oauth|not authenticated|sign[- ]?in)\b/i;
const RATE_LIMIT_PATTERN =
  /\b(?:429|rate[-\s]?limit(?:ed)?|quota|usage limit|resets_at|billing)\b/i;
const INCOMPATIBLE_HISTORY_PATTERN =
  /provider-private history is incompatible|reasoning replay .* provider attribution/i;
/**
 * The other thing MSP reports as incompatible history, and it is not a route
 * change: an image in the session that the model behind Muse cannot carry.
 * Same recovery — only a session without it can run — but saying "reasoning
 * replay after a route change" sends the reader looking for a fault that is
 * not there, and hides the one thing that stops it recurring.
 */
const RETAINED_MEDIA_PATTERN = /retained media history is unsupported/i;

export interface TurnFailureClassification {
  /** A rebuild is owed before the next turn. */
  restart: { reason: string; fresh: boolean } | null;
  /**
   * Whether bb should rerun the prompt itself once the rebuild is done.
   *
   * Only where the rebuild *is* the fix. An expired login is not cleared by a
   * new session and a rate limit is not cleared by anything but time, so those
   * settle as failures and are left to the user and to bb's own retry policy —
   * the same division codex keeps, which restarts for them and reruns neither.
   */
  rerun: boolean;
  /** A typed hint bb's runtime acts on. */
  hint: ProviderRecoveryHint | null;
}

export function classifyTurnFailure(
  params: unknown,
): TurnFailureClassification {
  const parsed = mspTurnCompletedParamsSchema.safeParse(params);
  if (!parsed.success || parsed.data.terminal !== "failed") {
    return { restart: null, rerun: false, hint: null };
  }
  const message = parsed.data.error?.message ?? parsed.data.reason ?? "";
  if (message === "") {
    return { restart: null, rerun: false, hint: null };
  }

  /**
   * Muse cannot replay its own encrypted reasoning once the session's route
   * changes, and the offending item stays in the session, so only a session
   * without that history can run again.
   */
  if (RETAINED_MEDIA_PATTERN.test(message)) {
    return {
      restart: {
        reason:
          "Muse read an image into this session and the model behind it cannot carry media in history, so bb started a fresh session without it",
        fresh: true,
      },
      rerun: true,
      hint: null,
    };
  }

  if (INCOMPATIBLE_HISTORY_PATTERN.test(message)) {
    return {
      restart: {
        reason:
          "Muse could not replay this session's reasoning history after its route changed, so bb started a fresh session",
        fresh: true,
      },
      rerun: true,
      hint: null,
    };
  }

  if (AUTH_PATTERN.test(message)) {
    return {
      restart: {
        reason: "Muse session restarted after an authentication failure",
        fresh: false,
      },
      rerun: false,
      hint: { kind: "authRequired", message, retryable: false },
    };
  }

  if (RATE_LIMIT_PATTERN.test(message)) {
    return {
      restart: null,
      rerun: false,
      hint: { kind: "rateLimited", message, retryable: false },
    };
  }

  return { restart: null, rerun: false, hint: null };
}
