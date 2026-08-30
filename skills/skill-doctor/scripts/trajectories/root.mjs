/**
 * Shared root resolution and package loading for the vendored trajectory
 * pipeline. The data root is created fresh per run and holds normalized/,
 * state/, and its own node_modules/ so the skill directory stays read-only.
 */
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function resolveRoot(argv = []) {
  const idx = argv.indexOf("--root");
  const value = idx === -1 ? undefined : argv[idx + 1];
  if (!value) {
    throw new Error("--root PATH is required (each skill-doctor run uses a fresh data root)");
  }
  return resolve(value);
}

export async function loadTrajectoryPackage(root) {
  const pkgDir = join(root, "node_modules", "@letta-ai", "trajectory");
  if (!existsSync(join(pkgDir, "package.json"))) {
    throw new Error(
      `@letta-ai/trajectory is not installed under ${root}. Build the root with ingest.sh --root ${root}.`,
    );
  }
  const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
  let entry;
  try {
    entry = createRequire(join(root, "package.json")).resolve("@letta-ai/trajectory");
  } catch {
    const exp = pkg.exports?.["."] ?? pkg.exports;
    const rel =
      (typeof exp === "string" ? exp : exp?.import ?? exp?.default ?? exp?.require) ??
      pkg.module ??
      pkg.main ??
      "index.js";
    entry = join(pkgDir, typeof rel === "string" ? rel : rel.default);
  }
  const mod = await import(pathToFileURL(entry).href);
  const suffix = existsSync(join(pkgDir, "dist", "adapters", "grok-build", "index.js")) ? "+grok-build-patch" : "";
  return { ...mod, PACKAGE: `@letta-ai/trajectory@${pkg.version}${suffix}` };
}
