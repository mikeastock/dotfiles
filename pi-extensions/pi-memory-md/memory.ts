import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface MemoryFrontmatter {
  description: string;
  tags?: string[];
  created?: string;
  updated?: string;
  limit?: number;
}

export interface MemoryDocument {
  frontmatter: MemoryFrontmatter;
  content: string;
}

function quoteString(value: string): string {
  return JSON.stringify(value);
}

function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || "project";
}

function normalizeRepoUrl(repoUrl?: string): string | undefined {
  if (!repoUrl) return undefined;

  const trimmed = repoUrl.trim();
  if (trimmed.length === 0) return undefined;

  const sshMatch = trimmed.match(/^git@([^:]+):(.+?)(?:\.git)?$/);
  if (sshMatch) {
    return `${sshMatch[1]}/${sshMatch[2]}`.toLowerCase();
  }

  const httpsMatch = trimmed.match(/^https?:\/\/([^/]+)\/(.+?)(?:\.git)?$/);
  if (httpsMatch) {
    return `${httpsMatch[1]}/${httpsMatch[2]}`.toLowerCase();
  }

  return trimmed.replace(/\.git$/, "").toLowerCase();
}

export function resolveProjectKey(projectRoot: string, repoUrl?: string): string {
  const projectName = slugify(path.basename(projectRoot));
  const identifier = normalizeRepoUrl(repoUrl) ?? path.resolve(projectRoot);
  const hash = crypto.createHash("sha1").update(identifier).digest("hex").slice(0, 8);
  return `${projectName}-${hash}`;
}

function parseFrontmatterValue(rawValue: string): string | number | string[] {
  const value = rawValue.trim();
  if (value.startsWith("[") && value.endsWith("]")) {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.some((item) => typeof item !== "string")) {
      throw new Error("Frontmatter arrays must contain only strings");
    }
    return parsed;
  }

  if (/^-?\d+$/.test(value)) {
    return Number(value);
  }

  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    if (value.startsWith('"')) {
      return JSON.parse(value);
    }
    return value.slice(1, -1);
  }

  return value;
}

export function parseMemoryDocument(text: string): MemoryDocument {
  const normalized = text.replace(/\r\n/g, "\n");
  if (!normalized.startsWith("---\n")) {
    throw new Error("Memory file must start with YAML frontmatter");
  }

  const closingIndex = normalized.indexOf("\n---\n", 4);
  if (closingIndex === -1) {
    throw new Error("Memory file frontmatter is missing a closing delimiter");
  }

  const frontmatterText = normalized.slice(4, closingIndex);
  const content = normalized.slice(closingIndex + 5).replace(/^\n/, "");
  const frontmatter: Record<string, unknown> = {};

  for (const line of frontmatterText.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    const separator = trimmed.indexOf(":");
    if (separator === -1) {
      throw new Error(`Invalid frontmatter line: ${line}`);
    }

    const key = trimmed.slice(0, separator).trim();
    const rawValue = trimmed.slice(separator + 1);
    frontmatter[key] = parseFrontmatterValue(rawValue);
  }

  if (typeof frontmatter.description !== "string" || frontmatter.description.trim().length === 0) {
    throw new Error("Memory file frontmatter must include a description");
  }

  if (frontmatter.tags !== undefined && (!Array.isArray(frontmatter.tags) || frontmatter.tags.some((tag) => typeof tag !== "string"))) {
    throw new Error("Memory file tags must be an array of strings");
  }

  if (frontmatter.limit !== undefined && typeof frontmatter.limit !== "number") {
    throw new Error("Memory file limit must be a number");
  }

  return {
    frontmatter: frontmatter as unknown as MemoryFrontmatter,
    content,
  };
}

export function formatMemoryDocument(frontmatter: MemoryFrontmatter, content: string): string {
  if (!frontmatter.description || frontmatter.description.trim().length === 0) {
    throw new Error("Memory files require a description");
  }

  const lines = ["---", `description: ${quoteString(frontmatter.description)}`];

  if (frontmatter.tags && frontmatter.tags.length > 0) {
    lines.push(`tags: ${JSON.stringify(frontmatter.tags)}`);
  }
  if (frontmatter.created) {
    lines.push(`created: ${quoteString(frontmatter.created)}`);
  }
  if (frontmatter.updated) {
    lines.push(`updated: ${quoteString(frontmatter.updated)}`);
  }
  if (frontmatter.limit !== undefined) {
    lines.push(`limit: ${frontmatter.limit}`);
  }

  lines.push("---", "", content.replace(/^\n+/, ""));
  return `${lines.join("\n").replace(/\n+$/, "\n")}\n`;
}

export function resolveMemoryFilePath(memoryDir: string, requestedPath: string): string {
  const normalizedInput = requestedPath.replace(/^@+/, "").trim();
  if (normalizedInput.length === 0) {
    throw new Error("Memory path is required");
  }

  if (path.isAbsolute(normalizedInput)) {
    throw new Error("Memory paths must be relative to the project memory directory");
  }

  const fullPath = path.resolve(memoryDir, normalizedInput);
  const relative = path.relative(memoryDir, fullPath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Memory paths must stay within the project memory directory");
  }

  return fullPath;
}

export function buildMemoryIndex(memoryDir: string): { text: string; fileCount: number } {
  const coreDir = path.join(memoryDir, "core");
  if (!fs.existsSync(coreDir)) {
    return { text: "", fileCount: 0 };
  }

  const stack = [coreDir];
  const files: string[] = [];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".md")) {
        files.push(fullPath);
      }
    }
  }

  files.sort();
  const lines = [
    "# Project Memory",
    "",
    "Available memory files (use memory_read to inspect full contents when needed):",
    "",
  ];

  let count = 0;
  for (const filePath of files) {
    const document = parseMemoryDocument(fs.readFileSync(filePath, "utf8"));
    const relativePath = path.relative(memoryDir, filePath);
    lines.push(`- ${relativePath}`);
    lines.push(`  Description: ${document.frontmatter.description}`);
    lines.push(`  Tags: ${(document.frontmatter.tags ?? []).join(", ") || "none"}`);
    lines.push("");
    count += 1;
  }

  return count === 0 ? { text: "", fileCount: 0 } : { text: lines.join("\n").trim(), fileCount: count };
}
