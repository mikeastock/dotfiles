import { execFile } from "node:child_process";
import { readFile, readlink, realpath } from "node:fs/promises";
import { platform } from "node:os";
import { promisify } from "node:util";
import { experimental_defineHostEntry } from "@get-bb/plugin-sdk/host";
import { closeOwnedPortProcesses } from "./close-owned-ports";
import { portScanContract, type PortRoot } from "./port-scan-contract";
import { attribute, parseCwds, parseDockerRows, parseListeners } from "./port-scan";
import type { OpenPort } from "./open-ports";
import { isBbInternalListener, parseProcessCommands } from "./port-processes";
import { macProcessEnvironment, threadIdFromEnvironment } from "./port-ownership";

const exec = promisify(execFile);

async function run(command: string, args: string[], signal: AbortSignal): Promise<string> {
  try {
    return (await exec(command, args, { signal, timeout: 5000, maxBuffer: 8 * 1024 * 1024 })).stdout;
  } catch (error) {
    if (signal.aborted) throw error;
    const result = error as { code?: unknown; stdout?: string };
    // lsof returns 1 for no matches and can report partial results.
    if (command === "lsof" && (result.code === 1 || result.stdout?.trim())) return result.stdout ?? "";
    throw error;
  }
}

async function scanPorts(roots: PortRoot[], signal: AbortSignal) {
  if (!roots.length) return { ports: [] };
  if (platform() !== "darwin" && platform() !== "linux") {
    throw new Error("Port discovery requires macOS or Linux");
  }
  const canonicalRoots = await Promise.all(roots.map(async (root) => ({
    ...root, path: await realpath(root.path).catch(() => root.path),
  })));
  const listeners = parseListeners(await run("lsof", ["-nP", "+c", "0", "-iTCP", "-sTCP:LISTEN"], signal));
  const pids = [...new Set(listeners.map((listener) => listener.pid))];
  const commands = new Map<number, string>();
  for (let start = 0; start < pids.length; start += 100) {
    try {
      const output = await run("ps", ["ww", "-p", pids.slice(start, start + 100).join(","), "-o", "pid=,args="], signal);
      for (const [pid, command] of parseProcessCommands(output)) commands.set(pid, command);
    } catch (error) {
      if (signal.aborted) throw error;
      // Processes can exit between the socket and command scans.
    }
  }
  const cwds = new Map<number, string>();
  if (platform() === "linux") {
    await Promise.all(pids.map(async (pid) => {
      try { cwds.set(pid, await readlink(`/proc/${pid}/cwd`)); } catch { /* Exited or inaccessible. */ }
    }));
  } else {
    for (let start = 0; start < pids.length; start += 100) {
      const batch = await run("lsof", ["-a", "-p", pids.slice(start, start + 100).join(","), "-d", "cwd", "-Fn"], signal);
      for (const [pid, cwd] of parseCwds(batch)) cwds.set(pid, cwd);
    }
  }
  const ports = new Map<string, OpenPort & { environmentId: string }>();
  const ownerByPid = new Map<number, string | undefined>();
  async function ownerThread(pid: number): Promise<string | undefined> {
    if (ownerByPid.has(pid)) return ownerByPid.get(pid);
    let owner: string | undefined;
    try {
      if (platform() === "linux") {
        owner = threadIdFromEnvironment(await readFile(`/proc/${pid}/environ`, "utf8"), "nul");
      } else {
        const command = commands.get(pid);
        if (command) {
          const full = await run("ps", ["eww", "-p", String(pid), "-o", "command="], signal);
          owner = threadIdFromEnvironment(macProcessEnvironment(command, full), "space");
        }
      }
    } catch (error) {
      if (signal.aborted) throw error;
      // Missing metadata means workspace-only attribution.
    }
    ownerByPid.set(pid, owner);
    return owner;
  }
  function add(cwd: string, detail: OpenPort) {
    const owner = attribute(cwd, canonicalRoots);
    if (!owner) return;
    const path = canonicalRoots.find((root) => root.environmentId === owner)!.path;
    // Multiple BB environments can refer to the same checkout.
    for (const root of canonicalRoots.filter((root) => root.path === path)) {
      const key = `${root.environmentId}:${detail.port}`;
      // Docker enriches an observed listener; it must not replace its PID,
      // bind address, or thread ownership with less specific metadata.
      ports.set(key, { environmentId: root.environmentId, ...detail, ...ports.get(key) });
    }
  }
  for (const listener of listeners) {
    if (isBbInternalListener(listener.processName, commands.get(listener.pid))) continue;
    const cwd = cwds.get(listener.pid);
    if (cwd && attribute(cwd, canonicalRoots)) {
      const ownerThreadId = await ownerThread(listener.pid);
      add(cwd, { ...listener, source: "process", ...(ownerThreadId ? { ownerThreadId } : {}) });
    }
  }
  try {
    const output = await run("docker", ["ps", "--format", '{{.ID}}\t{{.Names}}\t{{.Ports}}\t{{.Label "com.docker.compose.project.working_dir"}}\t{{.Label "com.docker.compose.service"}}'], signal);
    for (const row of parseDockerRows(output)) {
      const cwd = await realpath(row.workingDir).catch(() => row.workingDir);
      for (const binding of row.ports) add(cwd, {
        ...binding, source: "docker", container: row.name,
        ...(row.service ? { service: row.service } : {}),
      });
    }
  } catch (error) {
    if (signal.aborted) throw error;
    // Docker is optional; process listeners still apply when it is absent.
  }
  return { ports: [...ports.values()] };
}

export default experimental_defineHostEntry({
  contract: portScanContract,
  handlers: {
    async scan({ roots }, { signal }) {
      return scanPorts(roots, signal);
    },
    async closeOwnedPorts({ root, threadId, ports }, { signal }) {
      return closeOwnedPortProcesses(threadId, ports, async () =>
        (await scanPorts([root], signal)).ports,
        (pid) => { signal.throwIfAborted(); process.kill(pid, "SIGTERM"); },
      );
    },
  },
});
