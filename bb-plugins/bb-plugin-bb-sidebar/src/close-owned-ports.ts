import { z } from "zod";
import type { OpenPort } from "./open-ports";

export const ownedPortTargetSchema = z.object({
  port: z.number().int().min(1).max(65535),
  pid: z.number().int().min(2),
});
export const closePortsResultSchema = z.object({
  signalled: z.array(z.number()),
  skipped: z.array(z.number()),
  failed: z.array(z.number()),
});
export type OwnedPortTarget = z.infer<typeof ownedPortTargetSchema>;

/** Recheck each process against live ownership, never just a cached PID. */
export async function closeOwnedPortProcesses(
  threadId: string,
  targets: OwnedPortTarget[],
  scan: () => Promise<OpenPort[]>,
  terminate: (pid: number) => void,
) {
  const result: z.infer<typeof closePortsResultSchema> = { signalled: [], skipped: [], failed: [] };
  for (const pid of new Set(targets.map((target) => target.pid))) {
    const requested = targets.filter((target) => target.pid === pid);
    const current = await scan();
    const owned = current.filter((port) => port.pid === pid && port.source === "process" && port.ownerThreadId === threadId);
    if (!requested.some((target) => owned.some((port) => port.port === target.port))) {
      result.skipped.push(...requested.map((target) => target.port));
      continue;
    }
    try {
      terminate(pid);
      result.signalled.push(...requested.map((target) => target.port));
    } catch {
      result.failed.push(...requested.map((target) => target.port));
    }
  }
  return result;
}
