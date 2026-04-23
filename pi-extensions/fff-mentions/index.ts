/**
 * fff-mentions: @-mention autocomplete backed by FFF.
 *
 * Extracted from SamuelLHuber/pi-fff (https://github.com/SamuelLHuber/pi-fff)
 * -- only the @ autocomplete replacement; no find/grep tool overrides.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { CustomEditor, getAgentDir } from "@mariozechner/pi-coding-agent";
import type {
  AutocompleteItem,
  AutocompleteProvider,
  AutocompleteSuggestions,
} from "@mariozechner/pi-tui";
import { FileFinder } from "@ff-labs/fff-node";
import { mkdirSync } from "fs";
import { join } from "path";

const FFF_DB_DIR = join(getAgentDir(), "fff");
const FRECENCY_DB_PATH = join(FFF_DB_DIR, "frecency.mdb");
const HISTORY_DB_PATH = join(FFF_DB_DIR, "history.mdb");
const MENTION_MAX_RESULTS = 20;

function extractAtPrefix(textBeforeCursor: string): string | null {
  const match = textBeforeCursor.match(/(?:^|[ \t])(@(?:"[^"]*|[^\s]*))$/);
  return match?.[1] ?? null;
}

function parseAtPrefix(prefix: string): { raw: string; quoted: boolean } {
  if (prefix.startsWith('@"')) {
    return { raw: prefix.slice(2), quoted: true };
  }
  return { raw: prefix.slice(1), quoted: false };
}

function buildAtCompletionValue(path: string, quotedPrefix: boolean): string {
  if (quotedPrefix || path.includes(" ")) {
    return `@"${path}"`;
  }
  return `@${path}`;
}

class FffAtMentionProvider implements AutocompleteProvider {
  constructor(
    private base: AutocompleteProvider,
    private getItems: (
      query: string,
      quotedPrefix: boolean,
      signal: AbortSignal,
    ) => Promise<AutocompleteItem[]>,
  ) {}

  async getSuggestions(
    lines: string[],
    cursorLine: number,
    cursorCol: number,
    options: { signal: AbortSignal; force?: boolean },
  ): Promise<AutocompleteSuggestions | null> {
    const currentLine = lines[cursorLine] || "";
    const textBeforeCursor = currentLine.slice(0, cursorCol);
    const atPrefix = extractAtPrefix(textBeforeCursor);

    if (!atPrefix) {
      return this.base.getSuggestions(lines, cursorLine, cursorCol, options);
    }

    const { raw, quoted } = parseAtPrefix(atPrefix);
    if (options.signal.aborted) return null;

    try {
      const items = await this.getItems(raw, quoted, options.signal);
      if (options.signal.aborted) return null;
      if (items.length === 0) return null;
      return { items, prefix: atPrefix };
    } catch {
      return this.base.getSuggestions(lines, cursorLine, cursorCol, options);
    }
  }

  applyCompletion(
    lines: string[],
    cursorLine: number,
    cursorCol: number,
    item: AutocompleteItem,
    prefix: string,
  ) {
    return this.base.applyCompletion(lines, cursorLine, cursorCol, item, prefix);
  }
}

class FffEditor extends CustomEditor {
  constructor(
    tui: any,
    theme: any,
    keybindings: any,
    private createProvider: (base: AutocompleteProvider) => AutocompleteProvider,
  ) {
    super(tui, theme, keybindings);
  }

  override setAutocompleteProvider(provider: AutocompleteProvider): void {
    super.setAutocompleteProvider(this.createProvider(provider));
  }
}

export default function fffMentionsExtension(pi: ExtensionAPI) {
  let finder: FileFinder | null = null;
  let finderCwd: string | null = null;
  let activeCwd = process.cwd();

  try {
    mkdirSync(FFF_DB_DIR, { recursive: true });
  } catch {
    // ignore
  }

  async function ensureFinder(cwd: string): Promise<FileFinder> {
    if (finder && !finder.isDestroyed && finderCwd === cwd) return finder;
    if (finder && !finder.isDestroyed && finderCwd !== cwd) {
      finder.destroy();
      finder = null;
      finderCwd = null;
    }

    const result = FileFinder.create({
      basePath: cwd,
      frecencyDbPath: FRECENCY_DB_PATH,
      historyDbPath: HISTORY_DB_PATH,
      aiMode: true,
    });

    if (!result.ok) {
      throw new Error(`Failed to create FFF file finder: ${result.error}`);
    }

    finder = result.value;
    finderCwd = cwd;
    await finder.waitForScan(15000);
    return finder;
  }

  function destroyFinder() {
    if (finder && !finder.isDestroyed) {
      finder.destroy();
      finder = null;
      finderCwd = null;
    }
  }

  async function getMentionItems(
    query: string,
    quotedPrefix: boolean,
    signal: AbortSignal,
  ): Promise<AutocompleteItem[]> {
    if (signal.aborted) return [];
    const f = await ensureFinder(activeCwd);
    if (signal.aborted) return [];

    const searchResult = f.fileSearch(query, { pageSize: MENTION_MAX_RESULTS });
    if (!searchResult.ok) return [];

    return searchResult.value.items.slice(0, MENTION_MAX_RESULTS).map((item) => ({
      value: buildAtCompletionValue(item.relativePath, quotedPrefix),
      label: item.fileName,
      description: item.relativePath,
    }));
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      activeCwd = ctx.cwd;
      await ensureFinder(activeCwd);
      ctx.ui.setEditorComponent((tui: any, theme: any, keybindings: any) =>
        new FffEditor(tui, theme, keybindings, (baseProvider) =>
          new FffAtMentionProvider(baseProvider, getMentionItems),
        ),
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      ctx.ui.notify(`fff-mentions init failed: ${msg}`, "error");
    }
  });

  pi.on("session_shutdown", async (_event, ctx) => {
    ctx.ui.setEditorComponent(undefined);
    destroyFinder();
  });
}
