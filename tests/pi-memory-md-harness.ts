import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildMemoryIndex,
  formatMemoryDocument,
  parseMemoryDocument,
  resolveMemoryFilePath,
  resolveProjectKey,
} from "../pi-extensions/pi-memory-md/memory.ts";

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pi-memory-md-test-"));
  process.env.HOME = tmp;

  const workspace = path.join(tmp, "workspace", "dotfiles");
  fs.mkdirSync(workspace, { recursive: true });

  const localPath = path.join(tmp, "memory-store");
  const projectKey = resolveProjectKey(workspace);
  const projectMemoryDir = path.join(localPath, projectKey);
  fs.mkdirSync(path.join(projectMemoryDir, "core", "user"), { recursive: true });
  fs.mkdirSync(path.join(projectMemoryDir, "reference"), { recursive: true });

  const document = formatMemoryDocument(
    {
      description: "User code style preferences",
      tags: ["user", "style"],
      created: "2026-03-11",
      updated: "2026-03-11",
    },
    "# Preferences\n\n- Prefer 2-space indentation\n",
  );
  fs.writeFileSync(path.join(projectMemoryDir, "core", "user", "preferences.md"), document);
  fs.writeFileSync(
    path.join(projectMemoryDir, "reference", "notes.md"),
    formatMemoryDocument({ description: "Reference note", tags: ["reference"] }, "# Note\n"),
  );

  const parsed = parseMemoryDocument(document);
  assert.equal(parsed.frontmatter.description, "User code style preferences");
  assert.deepEqual(parsed.frontmatter.tags, ["user", "style"]);
  assert.match(parsed.content, /Prefer 2-space indentation/);

  assert.equal(
    resolveProjectKey(workspace, "git@github.com:mikeastock/dotfiles.git"),
    resolveProjectKey(path.join(tmp, "other-clone", "dotfiles"), "https://github.com/mikeastock/dotfiles.git"),
  );
  assert.notEqual(resolveProjectKey(workspace), resolveProjectKey(path.join(tmp, "other-clone", "dotfiles")));
  assert.notEqual(resolveProjectKey(workspace), resolveProjectKey(path.join(tmp, "workspace", "other-project")));

  const safePath = resolveMemoryFilePath(projectMemoryDir, "@core/user/preferences.md");
  assert.equal(safePath, path.join(projectMemoryDir, "core", "user", "preferences.md"));
  assert.throws(() => resolveMemoryFilePath(projectMemoryDir, "../secrets.md"), /must stay within the project memory directory/);

  const index = buildMemoryIndex(projectMemoryDir);
  assert.equal(index.fileCount, 1);
  assert.match(index.text, /core\/user\/preferences\.md/);
  assert.match(index.text, /User code style preferences/);
  assert.doesNotMatch(index.text, /reference\/notes\.md/);

  console.log("pi-memory-md harness passed");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
