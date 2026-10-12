import { chmod, lstat } from "node:fs/promises";
import { museDataDir } from "./paths.js";

/**
 * Muse stores the deletion authority beside its durable sessions and refuses
 * to create it below a group- or world-writable data directory. Linux package
 * and provisioning defaults commonly leave `~/.local/share/muse` as 0775,
 * which makes `session/start` fail with `UnsafePath` before an agent can run.
 *
 * Remove only write access that Muse itself refuses. The directory must be a
 * real directory owned by this process; never follow a link or change another
 * user's path while preparing a provider session.
 */
export async function ensureMuseDataDirSafe(
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const dataDir = museDataDir(env);
  let stats;
  try {
    stats = await lstat(dataDir);
  } catch (error) {
    if (isMissing(error)) {
      /** Muse will create a missing data directory under the user's umask. */
      return;
    }
    throw error;
  }

  if (stats.isSymbolicLink() || !stats.isDirectory()) {
    throw new Error(
      `Muse data directory must be a real directory, not a link or file: ${dataDir}`,
    );
  }

  const uid = typeof process.getuid === "function" ? process.getuid() : null;
  if (uid !== null && stats.uid !== uid) {
    throw new Error(
      `Muse data directory is not owned by the current user: ${dataDir}`,
    );
  }

  const currentMode = stats.mode & 0o7777;
  const safeMode = currentMode & ~0o022;
  if (safeMode !== currentMode) {
    await chmod(dataDir, safeMode);
  }
}

function isMissing(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    "code" in error &&
    (error as { code?: unknown }).code === "ENOENT"
  );
}
