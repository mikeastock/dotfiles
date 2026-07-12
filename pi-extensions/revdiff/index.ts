import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

export default function revdiffExtension(pi: ExtensionAPI): void {
  pi.registerCommand("revdiff", {
    description: "Launch revdiff, capture annotations, and send them to the agent",
    handler: async (args, ctx) => {
      if (ctx.mode !== "tui") {
        ctx.ui.notify("/revdiff requires the interactive Pi TUI", "warning");
        return;
      }

      if (!ctx.isIdle()) {
        ctx.ui.notify("Wait for the current turn to finish before launching revdiff", "warning");
        return;
      }

      const revdiffBin = process.env.REVDIFF_BIN || findInPath("revdiff");
      if (!revdiffBin) {
        ctx.ui.notify("revdiff binary not found. Install it or set REVDIFF_BIN.", "error");
        return;
      }

      const parsedArgs = stripOutputArgs(parseArgs(args));
      const tempDir = mkdtempSync(path.join(tmpdir(), "revdiff-pi-"));
      const outputFile = path.join(tempDir, "annotations.txt");
      const commandArgs = [...normalizeArgs(parsedArgs), `--output=${outputFile}`];

      const result = await runRevdiff(ctx, revdiffBin, commandArgs);
      const output = existsSync(outputFile) ? readFileSync(outputFile, "utf8").trim() : "";
      rmSync(tempDir, { recursive: true, force: true });

      if (result.error) {
        ctx.ui.notify(`Failed to launch revdiff: ${result.error.message}`, "error");
        return;
      }

      if (result.exitCode !== 0) {
        ctx.ui.notify(`revdiff exited with code ${result.exitCode}`, "warning");
        return;
      }

      if (!output) {
        ctx.ui.notify("revdiff complete — no annotations", "info");
        return;
      }

      ctx.ui.notify("Captured revdiff annotations; sending them to the agent", "info");
      pi.sendUserMessage(buildAgentPrompt(parsedArgs, output));
    },
  });
}

async function runRevdiff(
  ctx: ExtensionContext,
  revdiffBin: string,
  args: string[],
): Promise<{ exitCode: number; error?: Error }> {
  let error: Error | undefined;

  const exitCode = await ctx.ui.custom<number | null>((tui, _theme, _kb, done) => {
    tui.stop();
    process.stdout.write("\x1b[2J\x1b[H");

    const result = spawnSync(revdiffBin, args, {
      cwd: ctx.cwd,
      env: process.env,
      stdio: "inherit",
    });

    if (result.error) {
      error = result.error;
    }

    tui.start();
    tui.requestRender(true);
    done(result.status ?? (result.error ? 1 : 0));

    return { render: () => [], invalidate() {} };
  });

  return { exitCode: exitCode ?? 1, error };
}

function buildAgentPrompt(args: string[], annotations: string): string {
  const command = args.length > 0 ? `revdiff ${args.join(" ")}` : "revdiff";
  return [
    "Please address the following revdiff annotations.",
    "",
    `Original command: ${command}`,
    "",
    annotations,
  ].join("\n");
}

function normalizeArgs(args: string[]): string[] {
  if (args.length === 2 && args[0] === "--only") {
    return [`--only=${args[1]}`];
  }
  return args;
}

function stripOutputArgs(args: string[]): string[] {
  const stripped: string[] = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg) {
      continue;
    }
    if (arg === "--output" || arg === "-o") {
      i += 1;
      continue;
    }
    if (arg.startsWith("--output=") || arg.startsWith("-o=")) {
      continue;
    }
    stripped.push(arg);
  }
  return stripped;
}

function parseArgs(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let quote: '"' | "'" | undefined;
  let escaping = false;

  for (const char of input.trim()) {
    if (escaping) {
      current += char;
      escaping = false;
      continue;
    }

    if (char === "\\") {
      escaping = true;
      continue;
    }

    if (quote) {
      if (char === quote) {
        quote = undefined;
      } else {
        current += char;
      }
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current) {
        args.push(current);
        current = "";
      }
      continue;
    }

    current += char;
  }

  if (escaping) {
    current += "\\";
  }

  if (current) {
    args.push(current);
  }

  return args;
}

function findInPath(bin: string): string | undefined {
  const pathValue = process.env.PATH || "";
  for (const dir of pathValue.split(path.delimiter)) {
    if (!dir) {
      continue;
    }
    const candidate = path.join(dir, bin);
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return undefined;
}
