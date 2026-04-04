import type { Message } from "@mariozechner/pi-ai";

export function buildFinalPrompt(args: {
  goal: string;
  generatedPrompt: string;
  parentSession: string | undefined;
}): string {
  const { goal, generatedPrompt, parentSession } = args;
  if (!parentSession) return `${goal}\n\n${generatedPrompt}`;
  return `${goal}\n\n/skill:session-query\n\n**Parent session:** \`${parentSession}\`\n\n${generatedPrompt}`;
}

export function buildInitialUserMessage(finalPrompt: string, timestamp = Date.now()): Message {
  return {
    role: "user",
    content: [{ type: "text", text: finalPrompt }],
    timestamp,
  };
}
