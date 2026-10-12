import { mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { museConfigDir } from "../msp/paths.js";

/**
 * Muse reads its MCP servers from `settings.json` in its config directory, and
 * `muse serve` takes no per-session tool channel. Writing bb's proxy into the
 * user's own config would leak bb tools into their terminal sessions and mutate
 * a file bb does not own, so the bridge builds a private config directory
 * instead: the user's settings plus one added MCP server, with everything else
 * — credentials first of all — symlinked back to the real directory so the
 * session is the same account, the same skills, and the same session store.
 */

export interface MuseMcpServerSpec {
  command: string;
  args: string[];
  env: Record<string, string>;
}

export interface PrepareConfigHomeArgs {
  /** A per-thread directory under the plugin's own dataDir. */
  root: string;
  mcpServer: MuseMcpServerSpec | null;
  sourceConfigDir?: string;
}

const MCP_SERVER_NAME = "bb-bridge";

export async function prepareMuseConfigHome(
  args: PrepareConfigHomeArgs,
): Promise<string> {
  const sourceDir = args.sourceConfigDir ?? museConfigDir();
  const xdgHome = join(args.root, "xdg");
  const configDir = join(xdgHome, "muse");

  await rm(configDir, { recursive: true, force: true });
  await mkdir(configDir, { recursive: true });

  let entries: string[] = [];
  try {
    entries = await readdir(sourceDir);
  } catch {
    entries = [];
  }

  for (const entry of entries) {
    if (entry === "settings.json" || entry.startsWith(".")) {
      continue;
    }
    try {
      await symlink(join(sourceDir, entry), join(configDir, entry));
    } catch {
      /** A link bb cannot make is a file Muse will simply do without. */
    }
  }

  await writeFile(
    join(configDir, "settings.json"),
    `${JSON.stringify(await buildSettings(sourceDir, args.mcpServer), null, 2)}\n`,
    { mode: 0o600 },
  );

  return xdgHome;
}

export async function buildSettings(
  sourceDir: string,
  mcpServer: MuseMcpServerSpec | null,
): Promise<Record<string, unknown>> {
  // Muse requires this field even when the user's config has not been created.
  let settings: Record<string, unknown> = { schema_version: 1 };
  try {
    const raw: unknown = JSON.parse(
      await readFile(join(sourceDir, "settings.json"), "utf8"),
    );
    if (typeof raw === "object" && raw !== null && !Array.isArray(raw)) {
      settings = { schema_version: 1, ...(raw as Record<string, unknown>) };
    }
  } catch {
    settings = { schema_version: 1 };
  }

  const existing = settings.mcpServers;
  const servers: Record<string, unknown> =
    typeof existing === "object" && existing !== null && !Array.isArray(existing)
      ? { ...(existing as Record<string, unknown>) }
      : {};

  if (mcpServer === null) {
    delete servers[MCP_SERVER_NAME];
  } else {
    servers[MCP_SERVER_NAME] = {
      command: mcpServer.command,
      args: mcpServer.args,
      env: mcpServer.env,
    };
  }

  return Object.keys(servers).length === 0
    ? withoutMcpServers(settings)
    : { ...settings, mcpServers: servers };
}

function withoutMcpServers(
  settings: Record<string, unknown>,
): Record<string, unknown> {
  const next = { ...settings };
  delete next.mcpServers;
  return next;
}

export const MUSE_MCP_SERVER_NAME = MCP_SERVER_NAME;
