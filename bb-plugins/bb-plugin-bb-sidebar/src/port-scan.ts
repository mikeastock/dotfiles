// Adapted from bb-plugin-worktree-ports. See THIRD_PARTY_NOTICES.md.
// Pure parsing and attribution. Everything that touches the system lives in
// host.ts so this half stays unit-testable without spawning anything.
import { sep } from "node:path";
import type { PortRoot } from "./port-scan-contract";

export interface Listener {
  pid: number;
  processName: string;
  address: string;
  port: number;
}

export interface DockerRow {
  id: string;
  name: string;
  workingDir: string;
  /** com.docker.compose.service, or null for a container outside compose. */
  service: string | null;
  ports: { port: number; address: string }[];
}

/** `*:3000`, `127.0.0.1:3000`, `[::1]:3000`, `[::]:3000`. */
function parseAddressPort(
  value: string,
): { address: string; port: number } | null {
  const match = value.match(/^(?:\[([^\]]+)\]|([^:]+)):(\d+)$/);
  if (match === null) return null;
  const port = Number.parseInt(match[3] as string, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  const host = match[1] ?? match[2] ?? "*";
  return { address: host === "*" ? "0.0.0.0" : host, port };
}

/**
 * Columnar `lsof -nP -iTCP -sTCP:LISTEN` output. lsof escapes spaces in the
 * COMMAND column as `\x20`, so splitting on whitespace is safe.
 */
export function parseListeners(output: string): Listener[] {
  const listeners: Listener[] = [];
  for (const line of output.split("\n").slice(1)) {
    if (line.trim() === "") continue;
    const columns = line.trim().split(/\s+/);
    if (columns.length < 9) continue;
    const processName = (columns[0] as string).replace(/\\x([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
    const pid = Number.parseInt(columns[1] as string, 10);
    // NAME sits before the trailing "(LISTEN)" state.
    const name = columns[columns.length - 2] as string;
    if (!Number.isInteger(pid)) continue;
    const parsed = parseAddressPort(name);
    if (parsed === null) continue;
    listeners.push({ pid, processName, ...parsed });
  }
  return listeners;
}

/** Field-mode `lsof -a -p <pids> -d cwd -Fn` output: `p<pid>`, `fcwd`, `n<path>`. */
export function parseCwds(output: string): Map<number, string> {
  const cwds = new Map<number, string>();
  let pid: number | null = null;
  for (const line of output.split("\n")) {
    if (line.startsWith("p")) {
      const parsed = Number.parseInt(line.slice(1), 10);
      pid = Number.isInteger(parsed) ? parsed : null;
    } else if (line.startsWith("n") && pid !== null && !cwds.has(pid)) {
      cwds.set(pid, line.slice(1));
    }
  }
  return cwds;
}

/** `docker ps` rows: id \t name \t ports \t compose working dir \t compose service. */
export function parseDockerRows(output: string): DockerRow[] {
  const rows: DockerRow[] = [];
  for (const line of output.split("\n")) {
    if (line.trim() === "") continue;
    const [id, name, ports, workingDir, service] = line.split("\t");
    if (id === undefined || name === undefined || workingDir === undefined) continue;
    if (workingDir.trim() === "") continue;
    rows.push({
      id,
      name,
      workingDir: workingDir.trim(),
      service: service === undefined || service.trim() === "" ? null : service.trim(),
      ports: parseDockerPorts(ports ?? ""),
    });
  }
  return rows;
}

/**
 * `0.0.0.0:21785->6379/tcp, [::]:21785->6379/tcp` — only published mappings
 * (those with `->`) reach the host, and the IPv4/IPv6 pair is one port.
 */
export function parseDockerPorts(value: string): { port: number; address: string }[] {
  const seen = new Map<number, string>();
  for (const entry of value.split(",")) {
    const arrow = entry.indexOf("->");
    if (arrow === -1 || !entry.trim().endsWith("/tcp")) continue;
    const published = entry.slice(0, arrow).trim();
    const parsed = parseAddressPort(published);
    if (parsed === null) continue;
    // Prefer the IPv4 binding when a port is published on both families.
    if (!seen.has(parsed.port) || parsed.address.includes(".")) {
      seen.set(parsed.port, parsed.address);
    }
  }
  return [...seen].map(([port, address]) => ({ port, address }));
}

/**
 * The worktree owning a path — longest match wins, so a chain worktree nested
 * under another root is attributed to itself rather than its parent.
 */
export function attribute(path: string, roots: PortRoot[]): string | null {
  let best: PortRoot | null = null;
  for (const root of roots) {
    if (path !== root.path && !path.startsWith(root.path.replace(/\/+$/, "") + sep)) {
      continue;
    }
    if (best === null || root.path.length > best.path.length) best = root;
  }
  return best === null ? null : best.environmentId;
}

