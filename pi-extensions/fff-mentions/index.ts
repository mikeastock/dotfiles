/**
 * fff-mentions: @-mention autocomplete backed by FFF.
 *
 * Extracted from SamuelLHuber/pi-fff (https://github.com/SamuelLHuber/pi-fff)
 * -- only the @ autocomplete replacement; no find/grep tool overrides.
 */

import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import { CustomEditor } from "@mariozechner/pi-coding-agent";
import type {
  AutocompleteItem,
  AutocompleteProvider,
  AutocompleteSuggestions,
} from "@mariozechner/pi-tui";
import { FileFinder } from "@ff-labs/fff-node";
import type { MixedItem } from "@ff-labs/fff-node";

const MENTION_MAX_RESULTS = 20;

function extractAtPrefix(textBeforeCursor: string): string | null {
  const match = textBeforeCursor.match(/(?:^|[ \t])(@(?:"[^"]*|[^\s]*))$/);
  return match?.[1] ?? null;
}

function buildAtCompletionValue(path: string): string {
  return path.includes(" ") ? `@"${path}"` : `@${path}`;
}

function createFffMentionProvider(
  getItems: (query: string, signal: AbortSignal) => Promise<AutocompleteItem[]>,
): AutocompleteProvider {
  return {
    async getSuggestions(
      lines: string[],
      cursorLine: number,
      cursorCol: number,
      options: { signal: AbortSignal; force?: boolean },
    ): Promise<AutocompleteSuggestions | null> {
      const currentLine = lines[cursorLine] || "";
      const prefix = extractAtPrefix(currentLine.slice(0, cursorCol));
      if (!prefix || options.signal.aborted) return null;

      const query = prefix.startsWith('@"') ? prefix.slice(2) : prefix.slice(1);
      const items = await getItems(query, options.signal);
      return options.signal.aborted || items.length === 0 ? null : { items, prefix };
    },

    applyCompletion(lines, cursorLine, cursorCol, item, prefix) {
      const currentLine = lines[cursorLine] || "";
      const before = currentLine.slice(0, cursorCol - prefix.length);
      const after = currentLine.slice(cursorCol);
      const newLine = before + item.value + after;
      return {
        lines: [...lines.slice(0, cursorLine), newLine, ...lines.slice(cursorLine + 1)],
        cursorLine,
        cursorCol: cursorCol - prefix.length + item.value.length,
      };
    },
  };
}

class FffEditor extends CustomEditor {
  private baseProvider: AutocompleteProvider | undefined;

  constructor(
    tui: any,
    theme: any,
    keybindings: any,
    private getMentionItems: (
      query: string,
      signal: AbortSignal,
    ) => Promise<AutocompleteItem[]>,
  ) {
    super(tui, theme, keybindings);
  }

  override setAutocompleteProvider(provider: AutocompleteProvider): void {
    this.baseProvider = provider;
    const mentionProvider = createFffMentionProvider(this.getMentionItems);
    const compositeProvider: AutocompleteProvider = {
      getSuggestions: async (lines, cursorLine, cursorCol, options) => {
        const mentionResult = await mentionProvider.getSuggestions(
          lines,
          cursorLine,
          cursorCol,
          options,
        );
        if (mentionResult) return mentionResult;
        return (
          this.baseProvider?.getSuggestions(lines, cursorLine, cursorCol, options) ?? null
        );
      },
      applyCompletion: (lines, cursorLine, cursorCol, item, prefix) => {
        if (prefix?.startsWith("@")) {
          return mentionProvider.applyCompletion!(
            lines,
            cursorLine,
            cursorCol,
            item,
            prefix,
          );
        }
        return (
          this.baseProvider?.applyCompletion?.(
            lines,
            cursorLine,
            cursorCol,
            item,
            prefix,
          ) ?? { lines, cursorLine, cursorCol }
        );
      },
    };
    super.setAutocompleteProvider(compositeProvider);
  }
}

export default function fffMentionsExtension(pi: ExtensionAPI) {
  let finder: FileFinder | null = null;
  let finderCwd: string | null = null;
  let activeCwd = process.cwd();

  async function ensureFinder(cwd: string): Promise<FileFinder> {
    if (finder && !finder.isDestroyed && finderCwd === cwd) return finder;
    if (finder && !finder.isDestroyed && finderCwd !== cwd) {
      finder.destroy();
      finder = null;
      finderCwd = null;
    }

    const result = FileFinder.create({
      basePath: cwd,
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
    signal: AbortSignal,
  ): Promise<AutocompleteItem[]> {
    if (signal.aborted) return [];
    const f = await ensureFinder(activeCwd);
    if (signal.aborted) return [];

    const searchResult = f.mixedSearch(query, { pageSize: MENTION_MAX_RESULTS });
    if (!searchResult.ok) return [];

    return searchResult.value.items.slice(0, MENTION_MAX_RESULTS).map((mixed: MixedItem) => {
      if (mixed.type === "directory") {
        return {
          value: buildAtCompletionValue(mixed.item.relativePath),
          label: mixed.item.dirName,
          description: mixed.item.relativePath,
        };
      }
      return {
        value: buildAtCompletionValue(mixed.item.relativePath),
        label: mixed.item.fileName,
        description: mixed.item.relativePath,
      };
    });
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      activeCwd = ctx.cwd;
      await ensureFinder(activeCwd);
      ctx.ui.setEditorComponent((tui: any, theme: any, keybindings: any) =>
        new FffEditor(tui, theme, keybindings, getMentionItems),
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
