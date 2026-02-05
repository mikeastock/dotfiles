import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh";

const STATE_PATH = join(homedir(), ".pi", "agent", "per-model-thinking.json");

function modelKey(model: { provider: string; id: string }): string {
  return `${model.provider}/${model.id}`;
}

function isThinkingLevel(value: unknown): value is ThinkingLevel {
  return (
    value === "off" ||
    value === "minimal" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "xhigh"
  );
}

function replayThinkingByModel(entries: Array<Record<string, unknown>>): Map<string, ThinkingLevel> {
  const levels = new Map<string, ThinkingLevel>();
  let currentModel: string | undefined;
  let currentThinking: ThinkingLevel = "off";

  for (const entry of entries) {
    if (
      entry.type === "model_change" &&
      typeof entry.provider === "string" &&
      typeof entry.modelId === "string"
    ) {
      currentModel = `${entry.provider}/${entry.modelId}`;
      levels.set(currentModel, currentThinking);
      continue;
    }

    if (entry.type === "thinking_level_change" && isThinkingLevel(entry.thinkingLevel)) {
      currentThinking = entry.thinkingLevel;
      if (currentModel) {
        levels.set(currentModel, currentThinking);
      }
    }
  }

  return levels;
}

function entriesBeforeLatestModelChange(
  entries: Array<Record<string, unknown>>,
): Array<Record<string, unknown>> {
  for (let i = entries.length - 1; i >= 0; i -= 1) {
    if (entries[i].type === "model_change") {
      return entries.slice(0, i);
    }
  }
  return entries;
}

function loadGlobalState(): Map<string, ThinkingLevel> {
  try {
    const raw = readFileSync(STATE_PATH, "utf8");
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const map = new Map<string, ThinkingLevel>();
    for (const [key, value] of Object.entries(parsed)) {
      if (isThinkingLevel(value)) {
        map.set(key, value);
      }
    }
    return map;
  } catch {
    return new Map<string, ThinkingLevel>();
  }
}

function saveGlobalState(levels: Map<string, ThinkingLevel>): void {
  const serialized: Record<string, ThinkingLevel> = {};
  for (const [key, value] of levels) {
    serialized[key] = value;
  }

  mkdirSync(dirname(STATE_PATH), { recursive: true });
  writeFileSync(STATE_PATH, `${JSON.stringify(serialized, null, 2)}\n`, "utf8");
}

export default function (pi: ExtensionAPI) {
  const thinkingByModel = new Map<string, ThinkingLevel>();

  pi.on("session_start", async (_event, ctx) => {
    thinkingByModel.clear();

    for (const [key, level] of loadGlobalState()) {
      thinkingByModel.set(key, level);
    }

    const sessionLevels = replayThinkingByModel(
      ctx.sessionManager.getBranch() as Array<Record<string, unknown>>,
    );
    for (const [key, level] of sessionLevels) {
      thinkingByModel.set(key, level);
    }

    if (ctx.model) {
      const key = modelKey(ctx.model);
      const savedLevel = thinkingByModel.get(key);
      if (savedLevel) {
        pi.setThinkingLevel(savedLevel);
        thinkingByModel.set(key, pi.getThinkingLevel());
      }
    }

    saveGlobalState(thinkingByModel);
  });

  pi.on("model_select", async (event, ctx) => {
    const branch = ctx.sessionManager.getBranch() as Array<Record<string, unknown>>;
    const historicalLevels = replayThinkingByModel(entriesBeforeLatestModelChange(branch));

    if (event.previousModel) {
      const previousKey = modelKey(event.previousModel);
      const previousLevel = historicalLevels.get(previousKey);
      if (previousLevel) {
        thinkingByModel.set(previousKey, previousLevel);
      }
    }

    const nextKey = modelKey(event.model);
    const savedLevel = thinkingByModel.get(nextKey) ?? historicalLevels.get(nextKey);
    if (savedLevel) {
      pi.setThinkingLevel(savedLevel);
    }

    thinkingByModel.set(nextKey, pi.getThinkingLevel());
    saveGlobalState(thinkingByModel);
  });
}
