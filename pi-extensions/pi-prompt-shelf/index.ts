/**
 * Prompt Shelf Extension
 *
 * Stash prompts from the editor into a per-session shelf instead of submitting them.
 * The shelf is always visible as a widget above the editor input.
 * Use the overlay to restore or delete shelved prompts.
 *
 * Shortcuts:
 *   Alt+S       — Shelve current editor text
 *   Alt+1..9    — Restore shelved prompt by number
 *   Alt+X       — Clear all shelved prompts
 *
 * Command:
 *   /shelf — Open shelf picker (restore/delete)
 */

import {
  CONFIG_DIR_NAME,
  type ExtensionAPI,
  type ExtensionContext,
} from "@earendil-works/pi-coding-agent";
import {
  Key,
  matchesKey,
  visibleWidth,
  truncateToWidth,
} from "@earendil-works/pi-tui";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";

interface ShelfItem {
  id: string;
  text: string;
  timestamp: number;
}

function shelfFile(cwd: string, sessionId: string): string {
  return join(cwd, CONFIG_DIR_NAME, "prompt-shelf", `${sessionId}.json`);
}

function loadShelf(
  cwd: string,
  sessionId: string,
): { items: ShelfItem[]; nextId: number } {
  try {
    const raw = readFileSync(shelfFile(cwd, sessionId), "utf-8");
    const data = JSON.parse(raw) as { items?: ShelfItem[]; nextId?: number };
    return {
      items: Array.isArray(data.items) ? data.items : [],
      nextId: typeof data.nextId === "number" ? data.nextId : 1,
    };
  } catch {
    return { items: [], nextId: 1 };
  }
}

function saveShelf(
  cwd: string,
  sessionId: string,
  items: ShelfItem[],
  nextId: number,
): void {
  const file = shelfFile(cwd, sessionId);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify({ items, nextId }, null, 2));
}

export default function (pi: ExtensionAPI) {
  let shelf: ShelfItem[] = [];
  let nextId = 1;
  let currentCtx: ExtensionContext | undefined;
  let currentCwd: string | undefined;
  let currentSessionId: string | undefined;

  function persist() {
    if (currentCwd && currentSessionId) {
      saveShelf(currentCwd, currentSessionId, shelf, nextId);
    }
  }

  function updateWidget() {
    const ctx = currentCtx;
    if (!ctx) return;

    if (shelf.length === 0) {
      ctx.ui.setWidget("prompt-shelf", undefined);
      return;
    }

    ctx.ui.setWidget("prompt-shelf", (_tui, theme) => {
      return {
        render(width: number) {
          const w = Math.max(width, 30);
          const lines: string[] = [];

          // Helper: build a bordered line that fits exactly w visible chars
          function borderedLine(content: string, contentWidth: number): string {
            const pad = Math.max(0, w - 4 - contentWidth); // 4 = "│ " + " │"
            return (
              theme.fg("border", "│") +
              " " +
              content +
              " ".repeat(pad) +
              " " +
              theme.fg("border", "│")
            );
          }

          // Top border with embedded title
          const title = " Prompt Shelf ";
          const topFill = w - 2 - title.length; // 2 for ╭╮
          lines.push(
            theme.fg("border", "╭─") +
              theme.fg("accent", title) +
              theme.fg("border", "─".repeat(Math.max(0, topFill - 1)) + "╮"),
          );

          // Prompt items (numbered)
          for (let i = 0; i < shelf.length; i++) {
            const item = shelf[i]!;
            const time = new Date(item.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            });

            const numPrefix = `${i + 1}. `;
            const firstLine = item.text.split("\n")[0] ?? "";
            const multilineTag = item.text.includes("\n") ? " [+lines]" : "";
            const timeStr = `  ${time}`;
            // 4 = "│ " + " │"
            const maxPreview =
              w - 4 - numPrefix.length - multilineTag.length - timeStr.length;
            const preview = truncateToWidth(
              firstLine,
              Math.max(0, maxPreview),
              "…",
            );

            const content =
              theme.fg("dim", numPrefix) +
              theme.fg("text", preview) +
              theme.fg("dim", multilineTag) +
              theme.fg("dim", timeStr);
            const contentWidth =
              numPrefix.length +
              visibleWidth(preview) +
              multilineTag.length +
              timeStr.length;

            lines.push(borderedLine(content, contentWidth));
          }

          // Bottom border with keyboard shortcuts (keys darker than actions)
          const hints = [
            [" alt+s ", "shelve"],
            [" alt+1-9 ", "restore"],
            [" alt+x ", "clear"],
          ];
          const sep = " · ";
          let hintsStr = "";
          let hintsWidth = 0;
          for (let i = 0; i < hints.length; i++) {
            if (i > 0) {
              hintsStr += theme.fg("border", sep);
              hintsWidth += sep.length;
            }
            hintsStr +=
              theme.fg("muted", hints[i]![0]) + theme.fg("dim", hints[i]![1]);
            hintsWidth += hints[i]![0].length + hints[i]![1].length;
          }
          hintsStr += " ";
          hintsWidth += 1;
          const bottomFill = w - 2 - hintsWidth; // 2 for ╰ and ╯
          const leftDashes = Math.max(1, bottomFill - 1); // -1 for trailing ─ before ╯
          lines.push(
            theme.fg("border", "╰" + "─".repeat(leftDashes)) +
              hintsStr +
              theme.fg("border", "─╯"),
          );

          return lines;
        },
        invalidate() {},
      };
    });
  }

  function shelveText(text: string, ctx: ExtensionContext) {
    const id = String(nextId++);
    const item: ShelfItem = { id, text, timestamp: Date.now() };
    shelf.push(item);
    persist();
    ctx.ui.setEditorText("");
    updateWidget();
    ctx.ui.notify(`Shelved (${shelf.length} total)`, "info");
  }

  function removeItem(id: string) {
    shelf = shelf.filter((item) => item.id !== id);
    persist();
    updateWidget();
  }

  function clearShelf() {
    shelf = [];
    persist();
    updateWidget();
  }

  async function openShelfPicker(ctx: ExtensionContext) {
    if (ctx.mode !== "tui") {
      ctx.ui.notify("/shelf requires the interactive Pi TUI", "warning");
      return;
    }

    if (shelf.length === 0) {
      ctx.ui.notify("Shelf is empty — use alt+s to shelve", "info");
      return;
    }

    const result = await ctx.ui.custom<{
      action: "restore" | "delete";
      item: ShelfItem;
    } | null>(
      (tui, theme, _kb, done) => {
        let selected = 0;

        function render(width: number): string[] {
          const w = Math.max(width, 30);
          const lines: string[] = [];

          // Helper: build a bordered line that fits exactly w visible chars
          function borderedLine(content: string, contentWidth: number): string {
            const pad = Math.max(0, w - 4 - contentWidth); // 4 = "│ " + " │"
            return (
              theme.fg("border", "│") +
              " " +
              content +
              " ".repeat(pad) +
              " " +
              theme.fg("border", "│")
            );
          }

          // Top border with title
          const title = " Prompt Shelf ";
          const topFill = w - 2 - title.length;
          lines.push(
            theme.fg("border", "╭─") +
              theme.fg("accent", title) +
              theme.fg("border", "─".repeat(Math.max(0, topFill - 1)) + "╮"),
          );

          // Prompt items
          for (let i = 0; i < shelf.length; i++) {
            const item = shelf[i]!;
            const isSelected = i === selected;
            const prefix = isSelected ? "▶ " : "  ";
            const time = new Date(item.timestamp).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            });

            const numPrefix = `${i + 1}. `;
            const firstLine = item.text.split("\n")[0] ?? "";
            const multilineTag = item.text.includes("\n") ? " [+lines]" : "";
            const timeStr = `  ${time}`;
            const maxPreview =
              w -
              4 -
              prefix.length -
              numPrefix.length -
              multilineTag.length -
              timeStr.length;
            const preview = truncateToWidth(
              firstLine,
              Math.max(0, maxPreview),
              "…",
            );

            const styledPrefix = isSelected
              ? theme.fg("accent", prefix)
              : theme.fg("dim", prefix);
            const styledNum = theme.fg("dim", numPrefix);
            const styledPreview = isSelected
              ? theme.fg("accent", preview)
              : theme.fg("text", preview);
            const content =
              styledPrefix +
              styledNum +
              styledPreview +
              theme.fg("dim", multilineTag) +
              theme.fg("dim", timeStr);
            const contentWidth =
              prefix.length +
              numPrefix.length +
              visibleWidth(preview) +
              multilineTag.length +
              timeStr.length;

            lines.push(borderedLine(content, contentWidth));
          }

          // Bottom border with help (keys darker than actions)
          const hints = [
            [" ↑↓ ", "navigate"],
            [" enter ", "restore"],
            [" d ", "delete"],
            [" esc ", "close"],
          ];
          const sep = " · ";
          let hintsStr = "";
          let hintsWidth = 0;
          for (let i = 0; i < hints.length; i++) {
            if (i > 0) {
              hintsStr += theme.fg("border", sep);
              hintsWidth += sep.length;
            }
            hintsStr +=
              theme.fg("muted", hints[i]![0]) + theme.fg("dim", hints[i]![1]);
            hintsWidth += hints[i]![0].length + hints[i]![1].length;
          }
          hintsStr += " ";
          hintsWidth += 1;
          const bottomFill = w - 2 - hintsWidth;
          const leftDashes = Math.max(1, bottomFill - 1);
          lines.push(
            theme.fg("border", "╰" + "─".repeat(leftDashes)) +
              hintsStr +
              theme.fg("border", "─╯"),
          );

          return lines;
        }

        return {
          render,
          invalidate() {},
          handleInput(data: string) {
            if (matchesKey(data, Key.escape)) {
              done(null);
            } else if (matchesKey(data, Key.up) && selected > 0) {
              selected--;
              tui.requestRender();
            } else if (
              matchesKey(data, Key.down) &&
              selected < shelf.length - 1
            ) {
              selected++;
              tui.requestRender();
            } else if (matchesKey(data, Key.enter)) {
              done({ action: "restore", item: shelf[selected]! });
            } else if (data === "d" || matchesKey(data, Key.delete)) {
              done({ action: "delete", item: shelf[selected]! });
            }
          },
        };
      },
      { overlay: true },
    );

    if (!result) return;

    if (result.action === "restore") {
      ctx.ui.setEditorText(result.item.text);
      removeItem(result.item.id);
    } else if (result.action === "delete") {
      removeItem(result.item.id);
      if (shelf.length > 0) {
        await openShelfPicker(ctx);
      } else {
        ctx.ui.notify("Shelf is empty — use alt+s to shelve", "info");
      }
    }
  }

  // Load shelf scoped to cwd + session ID
  pi.on("session_start", async (_event, ctx) => {
    currentCtx = ctx;
    currentCwd = ctx.cwd;
    currentSessionId = ctx.sessionManager.getSessionId();
    const loaded = loadShelf(currentCwd, currentSessionId);
    shelf = loaded.items;
    nextId = loaded.nextId;
    updateWidget();
  });

  // Shortcuts
  pi.registerShortcut(Key.alt("s"), {
    description: "Shelve current editor text",
    handler: async (ctx) => {
      const text = ctx.ui.getEditorText();
      if (!text.trim()) {
        ctx.ui.notify("Nothing to shelve", "warning");
        return;
      }
      shelveText(text, ctx);
    },
  });

  pi.registerShortcut(Key.alt("x"), {
    description: "Clear all shelved prompts",
    handler: async (ctx) => {
      if (shelf.length === 0) {
        ctx.ui.notify("Shelf is empty", "info");
        return;
      }
      const count = shelf.length;
      clearShelf();
      ctx.ui.notify(
        `Cleared ${count} shelved prompt${count === 1 ? "" : "s"}`,
        "info",
      );
    },
  });

  // Alt+1..9 to restore by number
  const digitKeys = ["1", "2", "3", "4", "5", "6", "7", "8", "9"] as const;
  for (const [index, key] of digitKeys.entries()) {
    const n = index + 1;
    pi.registerShortcut(Key.alt(key), {
      description: `Restore shelved prompt #${n}`,
      handler: async (ctx) => {
        if (n > shelf.length) {
          ctx.ui.notify(`No prompt #${n} on shelf`, "warning");
          return;
        }
        const item = shelf[n - 1]!;
        ctx.ui.setEditorText(item.text);
        removeItem(item.id);
        ctx.ui.notify(`Restored prompt #${n}`, "info");
      },
    });
  }

  // Command alias
  pi.registerCommand("shelf", {
    description: "Browse and restore shelved prompts",
    handler: async (_args, ctx) => {
      await openShelfPicker(ctx);
    },
  });
}
