import { wrapTextWithAnsi } from "@mariozechner/pi-tui";

export function wrapQuestionLines(prompt: string, width: number, indent = " "): string[] {
  const safeIndent = indent ?? "";
  const availableWidth = Math.max(1, width - safeIndent.length);
  const lines = wrapTextWithAnsi(prompt, availableWidth);
  return lines.map((line) => `${safeIndent}${line}`);
}
