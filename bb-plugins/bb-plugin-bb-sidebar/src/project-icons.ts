export const PROJECT_ICON_ROUTE =
  "/api/v1/plugins/bb-sidebar/http/project-icon";
export const PROJECT_ICONS_CHANNEL = "project-icons";

export const PROJECT_ICON_EXTENSIONS = [
  ".svg",
  ".png",
  ".ico",
  ".jpg",
  ".jpeg",
  ".gif",
  ".avif",
  ".webp",
] as const;

// Mirrors T3 Code's useful, framework-agnostic candidates. The root icon
// wins, then public assets, framework app icons, and finally generic assets.
export const PROJECT_ICON_CANDIDATES = [
  "favicon.svg",
  "favicon.ico",
  "favicon.png",
  "public/favicon.svg",
  "public/favicon.ico",
  "public/favicon.png",
  "app/favicon.ico",
  "app/favicon.png",
  "app/icon.svg",
  "app/icon.png",
  "app/icon.ico",
  "src/favicon.ico",
  "src/favicon.svg",
  "src/app/favicon.ico",
  "src/app/icon.svg",
  "src/app/icon.png",
  "assets/icon.svg",
  "assets/icon.png",
  "assets/logo.svg",
  "assets/logo.png",
  ".idea/icon.svg",
] as const;

export function normalizeProjectIconPath(input: string): string | null {
  const value = input.trim().replaceAll("\\", "/");
  if (
    value.length === 0 ||
    value.startsWith("/") ||
    /^[a-zA-Z]:\//.test(value) ||
    /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(value)
  ) {
    return null;
  }
  const parts = value.split("/").filter((part) => part !== ".");
  if (parts.length === 0 || parts.some((part) => part === ".." || !part)) {
    return null;
  }
  const path = parts.join("/");
  const lower = path.toLowerCase();
  return PROJECT_ICON_EXTENSIONS.some((extension) =>
    lower.endsWith(extension),
  )
    ? path
    : null;
}

const LINK_ICON_RE =
  /<link\b(?=[^>]*\brel=["'](?:icon|shortcut icon)["'])(?=[^>]*\bhref=["']([^"'?]+))[^>]*>/i;
const ICON_REL_RE = /\brel\s*:\s*["'](?:icon|shortcut icon)["']/i;
const ICON_HREF_RE = /\bhref\s*:\s*["']([^"'?]+)/i;

export function extractProjectIconHref(source: string): string | null {
  const htmlHref = source.match(LINK_ICON_RE)?.[1];
  if (htmlHref) return htmlHref;
  for (const run of source.split("}")) {
    if (!ICON_REL_RE.test(run)) continue;
    const href = run.match(ICON_HREF_RE)?.[1];
    if (href) return href;
  }
  return null;
}

export function iconPathsForHref(href: string): string[] {
  const withoutSuffix = href.split(/[?#]/, 1)[0]?.trim() ?? "";
  if (
    withoutSuffix.length === 0 ||
    withoutSuffix.startsWith("//") ||
    /^[a-zA-Z][a-zA-Z\d+.-]*:/.test(withoutSuffix)
  ) {
    return [];
  }
  let decoded: string;
  try {
    decoded = decodeURIComponent(withoutSuffix);
  } catch {
    return [];
  }
  const clean = decoded.replace(/^\/+/, "").replace(/^\.\//, "");
  const normalized = normalizeProjectIconPath(clean);
  if (!normalized) return [];
  return [...new Set([`public/${normalized}`, normalized])];
}

export function projectIconUrl(projectId: string, revision: number): string {
  const query = new URLSearchParams({
    projectId,
    revision: String(revision),
  });
  return `${PROJECT_ICON_ROUTE}?${query}`;
}
