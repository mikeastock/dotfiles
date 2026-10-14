// diffr's row painter reads a Palette. Build it from bb's active code theme
// (a VS Code theme document), so the diff matches bb's own code views and
// follows the user's palette and light/dark choice.
import type { PluginCodeThemeData } from "@get-bb/plugin-sdk/app";
import type { Palette } from "../vendor/diffr/theme/palette";

const HEX = /^#[0-9a-fA-F]{6}/;

/** `#rrggbb` from `#rrggbb[aa]`, or undefined for anything else. */
function hex(value: string | undefined): string | undefined {
  return value !== undefined && HEX.test(value) ? value.slice(0, 7) : undefined;
}

function luminance(color: string) {
  const channel = (i: number) => parseInt(color.slice(i, i + 2), 16) / 255;
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

export function mix(color: string, other: string, amount: number) {
  const channel = (i: number) =>
    Math.round(parseInt(color.slice(i, i + 2), 16) * (1 - amount) + parseInt(other.slice(i, i + 2), 16) * amount);
  return `#${[1, 3, 5].map((i) => channel(i).toString(16).padStart(2, "0")).join("")}`;
}

/**
 * TextMate scopes to try for each tree-sitter capture diffr emits, most
 * specific first. A capture not listed falls back through its parents
 * (`keyword.return` → `keyword`).
 */
const CAPTURE_SCOPES: Record<string, string[]> = {
  attribute: ["entity.other.attribute-name"],
  boolean: ["constant.language.boolean", "constant.language"],
  character: ["constant.character", "string"],
  comment: ["comment"],
  "comment.documentation": ["comment.block.documentation", "comment"],
  constant: ["variable.other.constant", "constant"],
  "constant.builtin": ["constant.language", "constant"],
  "constant.numeric": ["constant.numeric"],
  constructor: ["entity.name.type.class", "entity.name.type", "support.class"],
  embedded: ["meta.embedded", "source"],
  escape: ["constant.character.escape"],
  function: ["entity.name.function"],
  "function.builtin": ["support.function", "entity.name.function"],
  "function.call": ["entity.name.function"],
  "function.macro": ["entity.name.function.macro", "entity.name.function"],
  "function.method": ["entity.name.function.member", "entity.name.function"],
  keyword: ["keyword.control", "keyword", "storage.type"],
  "keyword.operator": ["keyword.operator"],
  label: ["entity.name.label", "entity.name"],
  module: ["entity.name.namespace", "entity.name.type.module"],
  namespace: ["entity.name.namespace", "entity.name.type.module"],
  number: ["constant.numeric"],
  operator: ["keyword.operator"],
  property: ["variable.other.property", "support.type.property-name", "variable.other.object.property"],
  punctuation: ["punctuation"],
  "punctuation.bracket": ["punctuation.definition.block", "punctuation"],
  "punctuation.delimiter": ["punctuation.separator", "punctuation"],
  "punctuation.special": ["punctuation.definition.template-expression", "punctuation"],
  string: ["string"],
  "string.escape": ["constant.character.escape"],
  "string.regexp": ["string.regexp", "string"],
  "string.special": ["string.other", "string"],
  tag: ["entity.name.tag"],
  type: ["entity.name.type", "support.type"],
  "type.builtin": ["support.type.primitive", "support.type", "storage.type"],
  variable: ["variable.other.readwrite", "variable"],
  "variable.builtin": ["variable.language"],
  "variable.member": ["variable.other.property", "variable.other.object.property"],
  "variable.parameter": ["variable.parameter"],
};

/** Plain prefix selectors from a token rule; descendant selectors are skipped. */
function selectors(scope: string | readonly string[] | undefined): string[] {
  if (scope === undefined) return [];
  const list = typeof scope === "string" ? scope.split(",") : scope;
  return list.map((selector) => selector.trim()).filter((selector) => selector !== "" && !selector.includes(" "));
}

/** The foreground for a TextMate scope: the longest matching selector wins. */
function scopeColor(theme: PluginCodeThemeData, scope: string): string | undefined {
  let best: { length: number; color: string } | undefined;
  for (const rule of theme.tokenColors) {
    const color = hex(rule.settings.foreground);
    if (color === undefined) continue;
    for (const selector of selectors(rule.scope)) {
      if ((scope === selector || scope.startsWith(`${selector}.`)) && selector.length >= (best?.length ?? 0)) {
        best = { length: selector.length, color };
      }
    }
  }
  return best?.color;
}

function captureScopes(capture: string): string[] {
  const parts = capture.split(".");
  const scopes: string[] = [];
  while (parts.length) {
    scopes.push(...(CAPTURE_SCOPES[parts.join(".")] ?? []));
    parts.pop();
  }
  return scopes;
}

export function paletteFromCodeTheme(theme: PluginCodeThemeData): Palette {
  const colors = theme.colors;
  const bg = hex(colors["editor.background"]) ?? hex(theme.bg) ?? (theme.type === "light" ? "#ffffff" : "#1e1e1e");
  const fg = hex(colors["editor.foreground"]) ?? hex(theme.fg) ?? (theme.type === "light" ? "#1f2328" : "#d4d4d4");
  const isLight = luminance(bg) > 0.5;
  const muted = hex(colors["editorLineNumber.foreground"]) ?? mix(fg, bg, 0.45);
  const plus = hex(colors["gitDecoration.addedResourceForeground"]) ?? (isLight ? "#1a7f37" : "#3fb950");
  const minus = hex(colors["gitDecoration.deletedResourceForeground"]) ?? (isLight ? "#cf222e" : "#f85149");
  const delta = hex(colors["gitDecoration.modifiedResourceForeground"]) ?? (isLight ? "#9a6700" : "#d29922");
  const accent = scopeColor(theme, "entity.name.function") ?? hex(colors["focusBorder"]) ?? fg;
  const fileHeader = mix(bg, fg, isLight ? 0.06 : 0.08);
  const cache = new Map<string, string | undefined>();
  return {
    name: theme.name,
    isLight,
    bg,
    fg,
    muted,
    chrome: mix(bg, fg, 0.04),
    fileHeader,
    fileHeaderDir: mix(fg, fileHeader, 0.4),
    highlight: mix(bg, fg, 0.12),
    selection: mix(bg, "#3b8eea", isLight ? 0.2 : 0.3),
    addition: mix(bg, plus, isLight ? 0.1 : 0.12),
    deletion: mix(bg, minus, isLight ? 0.1 : 0.12),
    modification: mix(bg, delta, 0.12),
    readAddition: mix(bg, plus, 0.06),
    readDeletion: mix(bg, minus, 0.06),
    searchMatch: mix(bg, accent, 0.4),
    searchCurrent: delta,
    searchCurrentText: isLight ? fg : bg,
    addWord: mix(bg, plus, isLight ? 0.28 : 0.32),
    deleteWord: mix(bg, minus, isLight ? 0.28 : 0.32),
    addedText: plus,
    removedText: minus,
    accent,
    foldPlaceholder: mix(muted, fg, 0.35),
    guide: hex(colors["editorIndentGuide.background1"]) ?? hex(colors["editorIndentGuide.background"]) ?? mix(bg, fg, 0.18),
    focusWash: mix(bg, accent, 0.08),
    focusBrace: mix(bg, accent, 0.3),
    syntax: (capture) => {
      if (!cache.has(capture)) {
        const scope = captureScopes(capture).find((candidate) => scopeColor(theme, candidate) !== undefined);
        cache.set(capture, scope === undefined ? undefined : scopeColor(theme, scope));
      }
      return cache.get(capture);
    },
  };
}
