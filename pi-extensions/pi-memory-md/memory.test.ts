import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  buildMemoryIndex,
  formatMemoryDocument,
  parseMemoryDocument,
  resolveMemoryFilePath,
  resolveProjectKey,
} from "./memory";

const tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-memory-md-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    fs.rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("pi-memory-md memory helpers", () => {
  it("parses and formats memory documents", () => {
    const document = formatMemoryDocument(
      {
        description: "User code style preferences",
        tags: ["user", "style"],
        created: "2026-03-11",
        updated: "2026-03-11",
      },
      "# Preferences\n\n- Prefer 2-space indentation\n",
    );

    const parsed = parseMemoryDocument(document);

    expect(parsed.frontmatter.description).toBe("User code style preferences");
    expect(parsed.frontmatter.tags).toEqual(["user", "style"]);
    expect(parsed.content).toMatch(/Prefer 2-space indentation/);
  });

  it("normalizes remote URLs when resolving project keys", () => {
    const tmp = makeTempDir();
    const workspace = path.join(tmp, "workspace", "dotfiles");

    expect(resolveProjectKey(workspace, "git@github.com:mikeastock/dotfiles.git")).toBe(
      resolveProjectKey(path.join(tmp, "other-clone", "dotfiles"), "https://github.com/mikeastock/dotfiles.git"),
    );
    expect(resolveProjectKey(workspace)).not.toBe(resolveProjectKey(path.join(tmp, "other-clone", "dotfiles")));
    expect(resolveProjectKey(workspace)).not.toBe(resolveProjectKey(path.join(tmp, "workspace", "other-project")));
  });

  it("keeps resolved memory paths inside the project memory directory", () => {
    const tmp = makeTempDir();
    const projectMemoryDir = path.join(tmp, "memory-store", "dotfiles-12345678");
    fs.mkdirSync(path.join(projectMemoryDir, "core", "user"), { recursive: true });

    expect(resolveMemoryFilePath(projectMemoryDir, "@core/user/preferences.md")).toBe(
      path.join(projectMemoryDir, "core", "user", "preferences.md"),
    );
    expect(() => resolveMemoryFilePath(projectMemoryDir, "../secrets.md")).toThrow(
      /must stay within the project memory directory/,
    );
  });

  it("indexes only core markdown files", () => {
    const tmp = makeTempDir();
    const workspace = path.join(tmp, "workspace", "dotfiles");
    const localPath = path.join(tmp, "memory-store");
    const projectKey = resolveProjectKey(workspace);
    const projectMemoryDir = path.join(localPath, projectKey);

    fs.mkdirSync(path.join(projectMemoryDir, "core", "user"), { recursive: true });
    fs.mkdirSync(path.join(projectMemoryDir, "reference"), { recursive: true });

    fs.writeFileSync(
      path.join(projectMemoryDir, "core", "user", "preferences.md"),
      formatMemoryDocument(
        {
          description: "User code style preferences",
          tags: ["user", "style"],
          created: "2026-03-11",
          updated: "2026-03-11",
        },
        "# Preferences\n\n- Prefer 2-space indentation\n",
      ),
    );
    fs.writeFileSync(
      path.join(projectMemoryDir, "reference", "notes.md"),
      formatMemoryDocument({ description: "Reference note", tags: ["reference"] }, "# Note\n"),
    );

    const index = buildMemoryIndex(projectMemoryDir);

    expect(index.fileCount).toBe(1);
    expect(index.text).toMatch(/core\/user\/preferences\.md/);
    expect(index.text).toMatch(/User code style preferences/);
    expect(index.text).not.toMatch(/reference\/notes\.md/);
  });
});
