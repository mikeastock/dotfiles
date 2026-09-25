import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { cn } from "./lib/utils";

/**
 * `bb plugin build` hands Tailwind an input with no `@custom-variant dark`, so
 * a `dark:` utility compiles to `@media (prefers-color-scheme: dark)` and
 * follows the OS while bb switches theme with a class on <html>. Every themed
 * colour therefore has to come from src/theme.css instead, and these tests
 * fail the moment one creeps back.
 */

const ROOT = join(import.meta.dirname, "..");
const THEME_CSS = readFileSync(join(ROOT, "src/theme.css"), "utf8");
/** Rules only: the prose explains what the rules must not do. */
const THEME_RULES = THEME_CSS.replaceAll(/\/\*[\s\S]*?\*\//g, "");

/** Every shipped source file: src/**, minus tests, plus the app entry. */
function sourceFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...sourceFiles(path));
      continue;
    }
    if (/\.(test|spec)\.[jt]sx?$/.test(entry.name)) continue;
    if (/\.(tsx?|css)$/.test(entry.name)) files.push(path);
  }
  return files;
}

const SOURCES = [join(ROOT, "app.tsx"), ...sourceFiles(join(ROOT, "src"))];

/** `dark:` as a Tailwind variant: at a class-list boundary, not mid-word. */
const DARK_VARIANT = /(?:^|[\s"'`{(])dark:/;

describe("theme", () => {
  it("has no dark: utility left in shipped source", () => {
    const offenders = SOURCES.filter((path) => {
      // theme.css explains the ban; its prose is not a class list.
      if (path.endsWith("theme.css")) return false;
      return DARK_VARIANT.test(readFileSync(path, "utf8"));
    });
    expect(offenders.map((path) => path.slice(ROOT.length + 1))).toEqual([]);
  });

  it("pairs every themed custom property for both themes", () => {
    const light = cssBlock(THEME_RULES, ":root,\n.light {");
    const dark = cssBlock(THEME_RULES, ".dark {");
    const used = new Set<string>();
    for (const path of SOURCES) {
      if (path.endsWith(".css")) continue;
      for (const match of readFileSync(path, "utf8").matchAll(
        /var\((--bb-sidebar-[\w-]+)\)/g,
      )) {
        used.add(match[1]!);
      }
    }
    expect(used.size).toBeGreaterThan(10);
    for (const name of used) {
      expect(light, `${name} missing a light value`).toContain(`${name}:`);
      expect(dark, `${name} missing a dark value`).toContain(`${name}:`);
    }
  });

  it("keys the stylesheet off bb's theme class, never the OS", () => {
    expect(THEME_RULES).not.toContain("prefers-color-scheme");
    expect(THEME_RULES).toContain(".dark {");
  });

  // A font-size utility and an arbitrary colour both start `text-`; the merge
  // has to keep both, which is why the colour carries an explicit `color:`.
  it("keeps a size utility beside an arbitrary tone utility", () => {
    const merged = cn(
      "max-w-full truncate text-2xs font-medium",
      "text-[color:var(--bb-sidebar-tone-error)]",
    );
    expect(merged).toContain("text-2xs");
    expect(merged).toContain("text-[color:var(--bb-sidebar-tone-error)]");
  });

  // Only meaningful after `npm run build`; `npm run check` builds afterwards,
  // so this guards the artifact a developer already has on disk.
  it("emits no prefers-color-scheme in the built stylesheet", () => {
    const built = join(ROOT, "dist/app.css");
    if (!existsSync(built)) return;
    const css = readFileSync(built, "utf8");
    expect(css).not.toContain("prefers-color-scheme");
    expect(css).toContain(".dark .bb-sidebar-theme-light-only");
    expect(css).toMatch(/\.dark\s*\{/);
  });
});

/** The body of the rule that starts with `header`, brace-matched. */
function cssBlock(css: string, header: string): string {
  const start = css.indexOf(header);
  expect(start, `no ${header} block in src/theme.css`).toBeGreaterThan(-1);
  const end = css.indexOf("}", start);
  return css.slice(start, end);
}
