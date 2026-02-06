import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { ExtensionAPI, SessionEntry } from "@mariozechner/pi-coding-agent";

type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh";

type ModelChangeEntry = SessionEntry & {
  type: "model_change";
  provider: string;
  modelId: string;
};

type ThinkingLevelChangeEntry = SessionEntry & {
  type: "thinking_level_change";
  thinkingLevel: ThinkingLevel;
};

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

function isModelChangeEntry(entry: SessionEntry): entry is ModelChangeEntry {
  return (
    entry.type === "model_change" &&
    typeof (entry as { provider?: unknown }).provider === "string" &&
    typeof (entry as { modelId?: unknown }).modelId === "string"
  );
}

function isThinkingLevelChangeEntry(entry: SessionEntry): entry is ThinkingLevelChangeEntry {
  return (
    entry.type === "thinking_level_change" &&
    isThinkingLevel((entry as { thinkingLevel?: unknown }).thinkingLevel)
  );
}

function replayThinkingByModel(entries: SessionEntry[]): Map<string, ThinkingLevel> {
  const levels = new Map<string, ThinkingLevel>();
  let currentModel: string | undefined;
  let currentThinking: ThinkingLevel = "off";

  for (const entry of entries) {
    if (isModelChangeEntry(entry)) {
      currentModel = `${entry.provider}/${entry.modelId}`;
      levels.set(currentModel, currentThinking);
      continue;
    }

    if (isThinkingLevelChangeEntry(entry)) {
      currentThinking = entry.thinkingLevel;
      if (currentModel) {
        levels.set(currentModel, currentThinking);
      }
    }
  }

  return levels;
}

function entriesBeforeLatestModelChange(entries: SessionEntry[]): SessionEntry[] {
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

    const sessionLevels = replayThinkingByModel(ctx.sessionManager.getBranch());
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
    const branch = ctx.sessionManager.getBranch();
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
