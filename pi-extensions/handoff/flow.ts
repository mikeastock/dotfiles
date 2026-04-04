import type { PendingHandoff } from "./pending.js";

export function finalizeGeneratedHandoff(args: {
  generatedPrompt: string | null;
  finalPrompt: string;
}): { ok: true; finalPrompt: string } | { ok: false; cancelled: true } {
  if (args.generatedPrompt === null) return { ok: false, cancelled: true };
  return { ok: true, finalPrompt: args.finalPrompt };
}

export function queueToolHandoff(
  store: { set(value: PendingHandoff): void },
  pending: PendingHandoff,
  sendUserMessage: (message: string, options: { deliverAs: "followUp" }) => void,
): { ok: true } | { ok: false; error: string } {
  try {
    store.set(pending);
    sendUserMessage("/__handoff-complete", { deliverAs: "followUp" });
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export async function completePendingHandoff(
  store: { consume(): PendingHandoff | null },
  createSession: (pending: PendingHandoff) => Promise<{ cancelled: boolean }>,
): Promise<{ ok: true; cancelled: boolean } | { ok: false; error: string }> {
  const pending = store.consume();
  if (!pending) return { ok: false, error: "No pending handoff." };
  const result = await createSession(pending);
  return { ok: true, cancelled: result.cancelled };
}
