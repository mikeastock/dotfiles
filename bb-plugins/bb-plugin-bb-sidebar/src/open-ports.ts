import { z } from "zod";

export const openPortSchema = z.object({
  port: z.number().int().min(1).max(65535),
  processName: z.string().optional(),
  pid: z.number().int().optional(),
  address: z.string().optional(),
  source: z.enum(["process", "docker"]).optional(),
  container: z.string().optional(),
  service: z.string().optional(),
  ownerThreadId: z.string().optional(),
});
export type OpenPort = z.infer<typeof openPortSchema>;

export const portSnapshotSchema = z.object({
  groups: z.array(z.object({
    environmentId: z.string(),
    ports: z.array(openPortSchema),
  })),
});

export type PortSnapshot = z.infer<typeof portSnapshotSchema>;

export function portsByEnvironment(snapshot: PortSnapshot): Map<string, OpenPort[]> {
  const result = new Map<string, OpenPort[]>();
  for (const group of snapshot.groups) {
    const ports = new Map(result.get(group.environmentId)?.map((port) => [port.port, port]));
    for (const port of group.ports) ports.set(port.port, port);
    result.set(group.environmentId, [...ports.values()].sort((a, b) => a.port - b.port));
  }
  return result;
}
