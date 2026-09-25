import { toast } from "sonner";
import type { OwnedPortTarget } from "./close-owned-ports";

export async function promptToCloseSettledPorts(
  threadId: string,
  getPorts: () => Promise<{ ports: OwnedPortTarget[] }>,
  closePorts: (ports: OwnedPortTarget[]) => Promise<{ signalled: number[]; skipped: number[]; failed: number[] }>,
  isCurrent: () => boolean,
) {
  try {
    const { ports } = await getPorts();
    if (!ports.length || !isCurrent()) return;
    let closing = false;
    toast.message("Close this thread's ports?", {
      id: `settled-ports:${threadId}`,
      description: `Stop the processes listening on ${[...new Set(ports.map((port) => `:${port.port}`))].join(", ")}? This also closes any other ports those processes serve.`,
      duration: Infinity,
      cancel: { label: "Keep open", onClick: () => {} },
      action: {
        label: "Close ports",
        onClick: async () => {
          if (closing || !isCurrent()) return;
          closing = true;
          try {
            const result = await closePorts(ports);
            if (result.failed.length) {
              toast.error("Some port processes could not be stopped", {
                description: result.failed.map((port) => `:${port}`).join(", "),
              });
            } else if (result.signalled.length) {
              toast.success("Stop requested for port processes", {
                description: "Processes received a graceful shutdown request. Ports may take a moment to close.",
              });
            } else {
              toast.message("No matching thread-owned ports are still running");
            }
          } catch (error) {
            toast.error("Could not close thread ports", { description: error instanceof Error ? error.message : String(error) });
          }
        },
      },
    });
  } catch (error) {
    if (isCurrent()) toast.error("Thread settled, but its ports could not be checked", {
      description: error instanceof Error ? error.message : String(error),
    });
  }
}
