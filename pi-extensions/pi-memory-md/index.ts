import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { StringEnum } from "@mariozechner/pi-ai";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";
import {
  DEFAULT_MAX_BYTES,
  DEFAULT_MAX_LINES,
  formatSize,
  truncateHead,
} from "@mariozechner/pi-coding-agent";
import { Type } from "@sinclair/typebox";

export interface MemoryFrontmatter {
  description: string;
  tags?: string[];
  created?: string;
  updated?: string;
  limit?: number;
}

interface MemoryDocument {
  frontmatter: MemoryFrontmatter;
  content: string;
}

interface MemorySettings {
  enabled: boolean;
  repoUrl?: string;
  localPath: string;
  autoSync: {
    onSessionStart: boolean;
  };
  injection: "message-append" | "system-prompt";
}

function requireRepoUrl(settings: MemorySettings): string {
  const repoUrl = settings.repoUrl?.trim();
  if (!repoUrl) {
    throw new Error("pi-memory-md requires pi-memory-md.repoUrl in ~/.pi/agent/settings.json");
  }
  return repoUrl;
}

interface GitCommandResult {
  success: boolean;
  stdout: string;
  stderr: string;
  code: number;
}

interface SyncResult {
  success: boolean;
  message: string;
}

interface ProjectContext {
  cwd: string;
  projectRoot: string;
  projectName: string;
  repoUrl?: string;
  projectKey: string;
  memoryDir: string;
}

interface MemoryIndexEntry {
  relativePath: string;
  description: string;
  tags: string[];
}

interface ToolTextResult {
  content: Array<{ type: "text"; text: string }>;
  details: Record<string, unknown>;
}

const SETTINGS_KEY = "pi-memory-md";
const DEFAULT_LOCAL_PATH = path.join(os.homedir(), ".pi", "memory-md");
const MEMORY_MESSAGE_TYPE = "pi-memory-md";
const MEMORY_REFRESH_MESSAGE_TYPE = "pi-memory-md-refresh";
const INDEX_HEADER = "# Project Memory";
const INDEX_BODY_HINT = "Available memory files (use memory_read to inspect full contents when needed):";

const MemorySyncAction = StringEnum(["pull", "push", "status"] as const, {
  description: "Git operation to perform on the backing memory repository",
});

const MemorySearchTarget = StringEnum(["content", "tags", "description"] as const, {
  description: "Where to search inside memory files",
});

function textResult(text: string, details: Record<string, unknown> = {}): ToolTextResult {
  return { content: [{ type: "text", text }], details };
}

function currentDate(): string {
  return new Date().toISOString().slice(0, 10);
}

function expandHome(value: string): string {
  if (!value.startsWith("~")) return value;
  return path.join(os.homedir(), value.slice(1));
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

function loadSettings(): MemorySettings {
  const defaults: MemorySettings = {
    enabled: true,
    localPath: DEFAULT_LOCAL_PATH,
    autoSync: { onSessionStart: true },
    injection: "message-append",
  };

  const settingsPath = path.join(os.homedir(), ".pi", "agent", "settings.json");
  if (!fs.existsSync(settingsPath)) {
    return defaults;
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
    const value = ((parsed[SETTINGS_KEY] as Partial<MemorySettings> | undefined) ?? {}) as Partial<MemorySettings>;

    return {
      enabled: value.enabled ?? defaults.enabled,
      repoUrl: value.repoUrl?.trim() || undefined,
      localPath: expandHome(value.localPath ?? defaults.localPath),
      autoSync: {
        onSessionStart: value.autoSync?.onSessionStart ?? defaults.autoSync.onSessionStart,
      },
      injection: value.injection ?? defaults.injection,
    };
  } catch {
    return defaults;
  }
}

async function runGit(pi: ExtensionAPI, cwd: string, args: string[], signal?: AbortSignal): Promise<GitCommandResult> {
  try {
    const result = await pi.exec("git", args, { cwd, signal });
    return {
      success: result.code === 0,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
      code: result.code,
    };
  } catch (error) {
    return {
      success: false,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
      code: 1,
    };
  }
}

function isGitRepo(repoPath: string): boolean {
  return fs.existsSync(path.join(repoPath, ".git"));
}

async function discoverProjectContext(pi: ExtensionAPI, cwd: string, settings: MemorySettings): Promise<ProjectContext> {
  let projectRoot = cwd;
  let repoUrl: string | undefined;

  const topLevelResult = await runGit(pi, cwd, ["rev-parse", "--show-toplevel"]);
  if (topLevelResult.success) {
    const candidate = topLevelResult.stdout.trim();
    if (candidate.length > 0) {
      projectRoot = candidate;
    }
  }

  const remoteResult = await runGit(pi, projectRoot, ["config", "--get", "remote.origin.url"]);
  if (remoteResult.success) {
    const candidate = remoteResult.stdout.trim();
    if (candidate.length > 0) {
      repoUrl = candidate;
    }
  }

  const projectKey = resolveProjectKey(projectRoot, repoUrl);
  const memoryDir = path.join(settings.localPath, projectKey);

  return {
    cwd,
    projectRoot,
    projectName: path.basename(projectRoot),
    repoUrl,
    projectKey,
    memoryDir,
  };
}

function listMarkdownFiles(rootDir: string): string[] {
  if (!fs.existsSync(rootDir)) {
    return [];
  }

  const files: string[] = [];
  const stack = [rootDir];

  while (stack.length > 0) {
    const current = stack.pop()!;
    const entries = fs.readdirSync(current, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.name === ".git" || entry.name === "node_modules") {
        continue;
      }

      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name.endsWith(".md")) {
        files.push(fullPath);
      }
    }
  }

  return files.sort();
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

function readMemoryFile(filePath: string): MemoryDocument {
  return parseMemoryDocument(fs.readFileSync(filePath, "utf8"));
}

function tryReadMemoryFile(filePath: string): MemoryDocument | null {
  try {
    return readMemoryFile(filePath);
  } catch {
    return null;
  }
}

function writeMemoryFile(filePath: string, document: MemoryDocument): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, formatMemoryDocument(document.frontmatter, document.content));
}

function buildMemoryIndex(memoryDir: string): { text: string; fileCount: number } {
  const coreDir = path.join(memoryDir, "core");
  const files = listMarkdownFiles(coreDir);

  if (files.length === 0) {
    return { text: "", fileCount: 0 };
  }

  const entries: MemoryIndexEntry[] = [];
  for (const filePath of files) {
    const document = tryReadMemoryFile(filePath);
    if (!document) {
      continue;
    }

    entries.push({
      relativePath: path.relative(memoryDir, filePath),
      description: document.frontmatter.description,
      tags: document.frontmatter.tags ?? [],
    });
  }

  if (entries.length === 0) {
    return { text: "", fileCount: 0 };
  }

  const lines = [INDEX_HEADER, "", INDEX_BODY_HINT, ""];
  for (const entry of entries) {
    lines.push(`- ${entry.relativePath}`);
    lines.push(`  Description: ${entry.description}`);
    lines.push(`  Tags: ${entry.tags.length > 0 ? entry.tags.join(", ") : "none"}`);
    lines.push("");
  }

  return { text: lines.join("\n").trim(), fileCount: entries.length };
}

function ensureProjectStructure(memoryDir: string): void {
  for (const relativeDir of ["core/user", "core/project", "reference"]) {
    fs.mkdirSync(path.join(memoryDir, relativeDir), { recursive: true });
  }
}

function ensureDefaultFiles(memoryDir: string): string[] {
  const created: string[] = [];
  const defaults: Array<{ relativePath: string; document: MemoryDocument }> = [
    {
      relativePath: "core/user/identity.md",
      document: {
        frontmatter: {
          description: "User identity and background",
          tags: ["user", "identity"],
          created: currentDate(),
          updated: currentDate(),
        },
        content: "# User Identity\n\nCapture stable background information the agent should remember.\n",
      },
    },
    {
      relativePath: "core/user/preferences.md",
      document: {
        frontmatter: {
          description: "User habits, workflow, and coding preferences",
          tags: ["user", "preferences"],
          created: currentDate(),
          updated: currentDate(),
        },
        content: "# User Preferences\n\n- Note enduring preferences here.\n- Keep entries specific and easy to scan.\n",
      },
    },
    {
      relativePath: "core/project/overview.md",
      document: {
        frontmatter: {
          description: "Project context, architecture, and important conventions",
          tags: ["project", "overview"],
          created: currentDate(),
          updated: currentDate(),
        },
        content: "# Project Overview\n\nDescribe the project, important conventions, and constraints worth remembering.\n",
      },
    },
  ];

  for (const item of defaults) {
    const fullPath = path.join(memoryDir, item.relativePath);
    if (fs.existsSync(fullPath)) continue;
    writeMemoryFile(fullPath, item.document);
    created.push(item.relativePath);
  }

  return created;
}

function buildDirectoryTree(rootDir: string, maxDepth = 3, depth = 0): string[] {
  if (!fs.existsSync(rootDir) || depth > maxDepth) {
    return [];
  }

  const entries = fs
    .readdirSync(rootDir, { withFileTypes: true })
    .filter((entry) => entry.name !== ".git" && entry.name !== "node_modules")
    .sort((a, b) => a.name.localeCompare(b.name));

  const lines: string[] = [];
  for (const entry of entries) {
    const prefix = `${"  ".repeat(depth)}- `;
    lines.push(`${prefix}${entry.name}${entry.isDirectory() ? "/" : ""}`);
    if (entry.isDirectory()) {
      lines.push(...buildDirectoryTree(path.join(rootDir, entry.name), maxDepth, depth + 1));
    }
  }

  return lines;
}

function truncateForToolOutput(text: string, label: string): ToolTextResult {
  const truncation = truncateHead(text, {
    maxLines: DEFAULT_MAX_LINES,
    maxBytes: DEFAULT_MAX_BYTES,
  });

  if (!truncation.truncated) {
    return textResult(text);
  }

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-memory-md-"));
  const tempFile = path.join(tempDir, `${label}.txt`);
  fs.writeFileSync(tempFile, text);

  let resultText = truncation.content;
  resultText += `\n\n[Output truncated: showing ${truncation.outputLines} of ${truncation.totalLines} lines`;
  resultText += ` (${formatSize(truncation.outputBytes)} of ${formatSize(truncation.totalBytes)}).`;
  resultText += ` Full output saved to: ${tempFile}]`;

  return textResult(resultText, {
    truncated: true,
    fullOutputPath: tempFile,
    outputLines: truncation.outputLines,
    totalLines: truncation.totalLines,
  });
}

function hasMemoryFiles(memoryDir: string): boolean {
  return listMarkdownFiles(path.join(memoryDir, "core")).length > 0;
}

async function syncRepository(pi: ExtensionAPI, settings: MemorySettings, signal?: AbortSignal): Promise<SyncResult> {
  const repoUrl = requireRepoUrl(settings);

  if (fs.existsSync(settings.localPath) && !isGitRepo(settings.localPath)) {
    return {
      success: false,
      message: `Local memory path exists but is not a git repository: ${settings.localPath}`,
    };
  }

  if (!fs.existsSync(settings.localPath)) {
    fs.mkdirSync(path.dirname(settings.localPath), { recursive: true });
    const cloneResult = await runGit(pi, path.dirname(settings.localPath), ["clone", repoUrl, settings.localPath], signal);
    if (!cloneResult.success) {
      return { success: false, message: cloneResult.stderr || "Failed to clone memory repository" };
    }
    return { success: true, message: `Cloned memory repository to ${settings.localPath}` };
  }

  const pullResult = await runGit(pi, settings.localPath, ["pull", "--rebase", "--autostash"], signal);
  if (!pullResult.success) {
    return { success: false, message: pullResult.stderr || "Failed to pull memory repository" };
  }

  const updated = /Updating|Fast-forward|files? changed/i.test(pullResult.stdout);
  return {
    success: true,
    message: updated ? "Pulled latest memory changes" : "Memory repository already up to date",
  };
}

async function pushRepository(pi: ExtensionAPI, settings: MemorySettings, signal?: AbortSignal): Promise<SyncResult> {
  if (!isGitRepo(settings.localPath)) {
    return { success: false, message: `Memory repository is not initialized at ${settings.localPath}` };
  }

  const statusResult = await runGit(pi, settings.localPath, ["status", "--short"], signal);
  if (!statusResult.success) {
    return { success: false, message: statusResult.stderr || "Failed to inspect memory repository status" };
  }

  const hasChanges = statusResult.stdout.trim().length > 0;
  if (hasChanges) {
    const addResult = await runGit(pi, settings.localPath, ["add", "."], signal);
    if (!addResult.success) {
      return { success: false, message: addResult.stderr || "Failed to stage memory changes" };
    }

    const commitMessage = `chore(memory): update memory ${new Date().toISOString()}`;
    const commitResult = await runGit(pi, settings.localPath, ["commit", "-m", commitMessage], signal);
    if (!commitResult.success) {
      return { success: false, message: commitResult.stderr || "Failed to commit memory changes" };
    }
  }

  const pushResult = await runGit(pi, settings.localPath, ["push"], signal);
  if (!pushResult.success) {
    return { success: false, message: pushResult.stderr || "Failed to push memory repository" };
  }

  return {
    success: true,
    message: hasChanges ? "Committed and pushed memory changes" : "Memory repository already up to date",
  };
}

export default function piMemoryMd(pi: ExtensionAPI) {
  let settings = loadSettings();
  let project: ProjectContext | null = null;
  let cachedIndex = "";
  let memoryInjected = false;
  let syncPromise: Promise<SyncResult> | null = null;

  async function refreshProject(ctx: { cwd: string }) {
    settings = loadSettings();
    project = await discoverProjectContext(pi, ctx.cwd, settings);
    cachedIndex = buildMemoryIndex(project.memoryDir).text;
    memoryInjected = false;
  }

  async function ensureProjectReady(ctx: { cwd: string }, signal?: AbortSignal) {
    requireRepoUrl(settings);

    if (!project || project.cwd !== ctx.cwd) {
      await refreshProject(ctx);
    }

    if (syncPromise) {
      await syncPromise;
      syncPromise = null;
      if (project) {
        cachedIndex = buildMemoryIndex(project.memoryDir).text;
      }
    }
  }

  pi.on("session_start", async (_event, ctx) => {
    await refreshProject(ctx);

    if (!settings.enabled || !project) {
      return;
    }

    try {
      requireRepoUrl(settings);
    } catch (error) {
      if (ctx.hasUI) {
        ctx.ui.notify(error instanceof Error ? error.message : String(error), "warning");
      }
      return;
    }

    if (settings.autoSync.onSessionStart) {
      syncPromise = syncRepository(pi, settings).then((result) => {
        if (ctx.hasUI) {
          ctx.ui.notify(result.message, result.success ? "info" : "warning");
        }
        return result;
      });
    }

    if (ctx.hasUI) {
      if (hasMemoryFiles(project.memoryDir)) {
        const count = buildMemoryIndex(project.memoryDir).fileCount;
        ctx.ui.notify(`Memory ready for ${project.projectName}: ${count} indexed file${count === 1 ? "" : "s"}`, "info");
      } else {
        ctx.ui.notify(`Memory not initialized for ${project.projectName}. Use /memory-init to set it up.`, "info");
      }
    }
  });

  pi.on("before_agent_start", async (event, ctx) => {
    if (!settings.enabled) {
      return undefined;
    }

    try {
      requireRepoUrl(settings);
    } catch {
      return undefined;
    }

    await ensureProjectReady(ctx);
    if (!project) {
      return undefined;
    }

    if (!cachedIndex) {
      return undefined;
    }

    if (settings.injection === "system-prompt") {
      return {
        systemPrompt: `${event.systemPrompt}\n\n${cachedIndex}`,
      };
    }

    if (memoryInjected) {
      return undefined;
    }

    memoryInjected = true;
    return {
      message: {
        customType: MEMORY_MESSAGE_TYPE,
        content: cachedIndex,
        display: false,
      },
    };
  });

  pi.registerTool({
    name: "memory_init",
    label: "Memory Init",
    description: "Initialize the backing memory repository and create the default per-project memory structure.",
    parameters: Type.Object({
      force: Type.Optional(Type.Boolean({ description: "Recreate the default project files even when the project already exists" })),
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      await refreshProject(ctx);
      if (!project) {
        throw new Error("Unable to resolve project context");
      }
      const currentProject = project;

      const force = Boolean(params.force);
      const syncResult = await syncRepository(pi, settings, signal);
      if (!syncResult.success) {
        throw new Error(syncResult.message);
      }

      if (force && fs.existsSync(currentProject.memoryDir)) {
        fs.rmSync(currentProject.memoryDir, { recursive: true, force: true });
      }

      ensureProjectStructure(currentProject.memoryDir);
      const created = ensureDefaultFiles(currentProject.memoryDir);
      cachedIndex = buildMemoryIndex(currentProject.memoryDir).text;
      memoryInjected = false;

      const lines = [
        `Initialized memory for ${currentProject.projectName}.`,
        `Project key: ${currentProject.projectKey}`,
        `Path: ${currentProject.memoryDir}`,
      ];
      if (created.length > 0) {
        lines.push("", "Created files:", ...created.map((item) => `- ${item}`));
      }

      return textResult(lines.join("\n"), {
        path: currentProject.memoryDir,
        created,
      });
    },
  });

  pi.registerTool({
    name: "memory_sync",
    label: "Memory Sync",
    description: "Synchronize the backing memory git repository. Use status to inspect changes, pull to refresh from origin, and push to commit and publish local memory changes.",
    parameters: Type.Object({
      action: MemorySyncAction,
    }),
    async execute(_toolCallId, params, signal, _onUpdate, ctx) {
      await ensureProjectReady(ctx, signal);
      const action = params.action as "pull" | "push" | "status";

      if (action === "status") {
        if (!isGitRepo(settings.localPath)) {
          return textResult(`Memory repository is not initialized at ${settings.localPath}`, { initialized: false });
        }

        const statusResult = await runGit(pi, settings.localPath, ["status", "--short", "--branch"], signal);
        if (!statusResult.success) {
          throw new Error(statusResult.stderr || "Failed to inspect memory repository status");
        }

        const output = statusResult.stdout.trim() || "Memory repository is clean";
        return truncateForToolOutput(output, "memory-status");
      }

      const result = action === "pull" ? await syncRepository(pi, settings, signal) : await pushRepository(pi, settings, signal);
      if (!result.success) {
        throw new Error(result.message);
      }

      if (project) {
        cachedIndex = buildMemoryIndex(project.memoryDir).text;
      }

      return textResult(result.message, { action });
    },
  });

  pi.registerTool({
    name: "memory_read",
    label: "Memory Read",
    description: `Read a memory markdown file from the current project's memory directory. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.` ,
    parameters: Type.Object({
      path: Type.String({ description: "Relative path inside the current project's memory directory" }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      await ensureProjectReady(ctx);
      if (!project) {
        throw new Error("Unable to resolve project context");
      }
      const currentProject = project;

      const filePath = resolveMemoryFilePath(currentProject.memoryDir, params.path);
      if (!fs.existsSync(filePath)) {
        throw new Error(`Memory file not found: ${params.path}`);
      }

      const document = readMemoryFile(filePath);
      const lines = [
        `Path: ${path.relative(currentProject.memoryDir, filePath)}`,
        `Description: ${document.frontmatter.description}`,
        `Tags: ${(document.frontmatter.tags ?? []).join(", ") || "none"}`,
        "",
        document.content.trimEnd(),
      ];

      return truncateForToolOutput(lines.join("\n"), "memory-read");
    },
  });

  pi.registerTool({
    name: "memory_write",
    label: "Memory Write",
    description: "Create or update a memory markdown file in the current project's memory directory.",
    parameters: Type.Object({
      path: Type.String({ description: "Relative path inside the current project's memory directory" }),
      content: Type.String({ description: "Markdown body content to write" }),
      description: Type.String({ description: "Short frontmatter description for the file" }),
      tags: Type.Optional(Type.Array(Type.String({ description: "Tag" }))),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      await ensureProjectReady(ctx);
      if (!project) {
        throw new Error("Unable to resolve project context");
      }
      const currentProject = project;

      const filePath = resolveMemoryFilePath(currentProject.memoryDir, params.path);
      const existing = fs.existsSync(filePath) ? readMemoryFile(filePath) : undefined;
      const today = currentDate();
      const document: MemoryDocument = {
        frontmatter: {
          description: params.description,
          tags: params.tags,
          created: existing?.frontmatter.created ?? today,
          updated: today,
          limit: existing?.frontmatter.limit,
        },
        content: params.content.trimEnd() + "\n",
      };

      writeMemoryFile(filePath, document);
      cachedIndex = buildMemoryIndex(currentProject.memoryDir).text;
      memoryInjected = false;

      return textResult(`Wrote memory file ${path.relative(currentProject.memoryDir, filePath)}`, {
        path: path.relative(currentProject.memoryDir, filePath),
        description: params.description,
        tags: params.tags ?? [],
      });
    },
  });

  pi.registerTool({
    name: "memory_list",
    label: "Memory List",
    description: `List memory markdown files for the current project. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.` ,
    parameters: Type.Object({
      directory: Type.Optional(Type.String({ description: "Optional relative directory to list inside project memory" })),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      await ensureProjectReady(ctx);
      if (!project) {
        throw new Error("Unable to resolve project context");
      }
      const currentProject = project;

      const targetDir = params.directory ? resolveMemoryFilePath(currentProject.memoryDir, params.directory) : currentProject.memoryDir;
      if (!fs.existsSync(targetDir)) {
        return textResult(`Memory directory not found: ${params.directory}`);
      }

      const files = listMarkdownFiles(targetDir).map((filePath) => path.relative(currentProject.memoryDir, filePath));
      if (files.length === 0) {
        return textResult("No memory files found");
      }

      return truncateForToolOutput(files.map((file) => `- ${file}`).join("\n"), "memory-list");
    },
  });

  pi.registerTool({
    name: "memory_search",
    label: "Memory Search",
    description: `Search memory file content, descriptions, or tags for the current project. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.` ,
    parameters: Type.Object({
      query: Type.String({ description: "Case-insensitive search query" }),
      searchIn: MemorySearchTarget,
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      await ensureProjectReady(ctx);
      if (!project) {
        throw new Error("Unable to resolve project context");
      }
      const currentProject = project;

      const query = params.query.trim().toLowerCase();
      if (query.length === 0) {
        throw new Error("Search query cannot be empty");
      }

      const searchIn = params.searchIn as "content" | "tags" | "description";
      const matches: string[] = [];

      for (const filePath of listMarkdownFiles(currentProject.memoryDir)) {
        const document = tryReadMemoryFile(filePath);
        if (!document) {
          continue;
        }

        const relativePath = path.relative(currentProject.memoryDir, filePath);
        let matchedLine: string | undefined;

        if (searchIn === "description") {
          if (document.frontmatter.description.toLowerCase().includes(query)) {
            matchedLine = document.frontmatter.description;
          }
        } else if (searchIn === "tags") {
          const tags = document.frontmatter.tags ?? [];
          if (tags.some((tag) => tag.toLowerCase().includes(query))) {
            matchedLine = tags.join(", ");
          }
        } else {
          const contentLine = document.content
            .split("\n")
            .find((line) => line.toLowerCase().includes(query));
          if (contentLine) {
            matchedLine = contentLine.trim();
          }
        }

        if (!matchedLine) continue;

        matches.push(`${relativePath}\n  ${matchedLine || "(match)"}`);
      }

      if (matches.length === 0) {
        return textResult(`No memory matches for \"${params.query}\" in ${searchIn}`);
      }

      return truncateForToolOutput(matches.join("\n\n"), "memory-search");
    },
  });

  pi.registerTool({
    name: "memory_check",
    label: "Memory Check",
    description: `Show the current project's memory directory tree and files. Output is truncated to ${DEFAULT_MAX_LINES} lines or ${formatSize(DEFAULT_MAX_BYTES)}.` ,
    parameters: Type.Object({}),
    async execute(_toolCallId, _params, _signal, _onUpdate, ctx) {
      await ensureProjectReady(ctx);
      if (!project) {
        throw new Error("Unable to resolve project context");
      }
      const currentProject = project;

      if (!fs.existsSync(currentProject.memoryDir)) {
        return textResult(`Memory directory not found: ${currentProject.memoryDir}`);
      }

      const lines = [
        `Project: ${currentProject.projectName}`,
        `Project key: ${currentProject.projectKey}`,
        `Path: ${currentProject.memoryDir}`,
        "",
        ...buildDirectoryTree(currentProject.memoryDir),
      ];

      return truncateForToolOutput(lines.join("\n"), "memory-check");
    },
  });

  pi.registerCommand("memory-status", {
    description: "Show the current project's memory status",
    handler: async (_args, ctx) => {
      await ensureProjectReady(ctx);
      if (!project) return;

      try {
        requireRepoUrl(settings);
      } catch (error) {
        ctx.ui.notify(error instanceof Error ? error.message : String(error), "warning");
        return;
      }

      const fileCount = buildMemoryIndex(project.memoryDir).fileCount;
      const status = isGitRepo(settings.localPath) ? "git-backed" : "not initialized";
      ctx.ui.notify(
        `Memory: ${project.projectName} | ${fileCount} indexed file${fileCount === 1 ? "" : "s"} | ${status} | ${project.memoryDir}`,
        "info",
      );
    },
  });

  pi.registerCommand("memory-init", {
    description: "Initialize project memory",
    handler: async (_args, ctx) => {
      await ensureProjectReady(ctx);
      if (!project) return;

      const syncResult = await syncRepository(pi, settings);
      if (!syncResult.success) {
        ctx.ui.notify(syncResult.message, "error");
        return;
      }

      ensureProjectStructure(project.memoryDir);
      const created = ensureDefaultFiles(project.memoryDir);
      cachedIndex = buildMemoryIndex(project.memoryDir).text;
      memoryInjected = false;

      const detail = created.length > 0 ? ` Created ${created.length} starter file${created.length === 1 ? "" : "s"}.` : "";
      ctx.ui.notify(`Memory initialized for ${project.projectName}.${detail}`, "info");
    },
  });

  pi.registerCommand("memory-refresh", {
    description: "Refresh the in-memory index from disk",
    handler: async (_args, ctx) => {
      await ensureProjectReady(ctx);
      if (!project) return;

      const index = buildMemoryIndex(project.memoryDir);
      cachedIndex = index.text;
      const fileCount = index.fileCount;

      if (settings.injection === "message-append" && cachedIndex) {
        pi.sendMessage({
          customType: MEMORY_REFRESH_MESSAGE_TYPE,
          content: cachedIndex,
          display: false,
        });
        memoryInjected = true;
      } else {
        memoryInjected = false;
      }

      ctx.ui.notify(`Memory refreshed for ${project.projectName}: ${fileCount} indexed file${fileCount === 1 ? "" : "s"}`, "info");
    },
  });

  pi.registerCommand("memory-check", {
    description: "Show the current project's memory directory",
    handler: async (_args, ctx) => {
      await ensureProjectReady(ctx);
      if (!project) return;

      if (!fs.existsSync(project.memoryDir)) {
        ctx.ui.notify(`Memory directory not found: ${project.memoryDir}`, "warning");
        return;
      }

      const preview = buildDirectoryTree(project.memoryDir).slice(0, 20).join("\n");
      ctx.ui.notify(preview || `${project.memoryDir} is empty`, "info");
    },
  });
}
