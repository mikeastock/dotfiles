import { defineRpcContract } from "@get-bb/plugin-sdk";
import { z } from "zod";
import { openPortSchema } from "./open-ports";
import { ownedPortTargetSchema, closePortsResultSchema } from "./close-owned-ports";

const rootSchema = z.object({ environmentId: z.string(), path: z.string().min(1) });
export type PortRoot = z.infer<typeof rootSchema>;
export const portScanContract = defineRpcContract({
  closeOwnedPorts: {
    input: z.object({ root: rootSchema, threadId: z.string().min(1), ports: z.array(ownedPortTargetSchema).min(1).max(1000) }),
    output: closePortsResultSchema,
  },
  scan: {
    input: z.object({ roots: z.array(rootSchema).max(10000) }),
    output: z.object({
      ports: z.array(openPortSchema.extend({
        environmentId: z.string(),
      })),
    }),
  },
});
