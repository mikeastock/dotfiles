import { useRef, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import {
  experimental_useSidebarThreads as useSidebarThreads,
  useBbContext,
  useBbNavigate,
  useRpc,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { threadDisplayTitle } from "./inbox";
import { usePortalScopeProps } from "./lib/portal-scope";

/**
 * The sidebar's own delete confirmation. bb's generic one says only "Delete
 * thread?", which is easy to misread across a busy list; this one names the
 * thread and its project, and counts the children that go with it.
 */
export function DeleteThreadDialog({
  thread,
  open,
  onOpenChange,
}: {
  thread: PluginSidebarThread;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { projects, threads } = useSidebarThreads();
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const navigate = useBbNavigate();
  const context = useBbContext();
  const portalScope = usePortalScopeProps();
  const [busy, setBusy] = useState(false);
  const submitting = useRef(false);

  const project = projects.find((candidate) => candidate.id === thread.projectId);
  const projectName = project && !project.isPersonal ? project.name : "Personal";
  const title = threadDisplayTitle(thread);
  const childCount = countDescendants(thread.id, threads);

  const submit = async () => {
    if (submitting.current) return;
    submitting.current = true;
    setBusy(true);
    try {
      await rpc.call("deleteThread", { threadId: thread.id, childThreadsConfirmed: true });
      toast.success("Thread deleted", { description: title });
      if (context.threadId === thread.id) navigate.toCompose();
      onOpenChange(false);
    } catch (error) {
      toast.error("Could not delete thread", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (!next && busy) return; onOpenChange(next); }}>
      <Dialog.Portal>
        <Dialog.Overlay {...portalScope} className="fixed inset-0 z-50 bg-black/40" />
        <Dialog.Content
          {...portalScope}
          className="fixed left-1/2 top-1/2 z-50 box-border w-[calc(100%_-_2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border bg-popover p-5 text-popover-foreground shadow-lg outline-none"
        >
          <Dialog.Title className="text-sm font-semibold leading-5">Delete thread?</Dialog.Title>
          <div className="mt-3 rounded-md border border-border bg-background px-3 py-2">
            <div className="truncate text-sm font-medium" title={title}>{title}</div>
            <div className="truncate text-xs text-muted-foreground" title={projectName}>{projectName}</div>
          </div>
          <Dialog.Description className="mb-4 mt-3 text-xs leading-5 text-muted-foreground">
            {childCount > 0
              ? `This also deletes ${childCount === 1 ? "its 1 child thread" : `its ${childCount} child threads`}. This action cannot be undone.`
              : "This action cannot be undone."}
          </Dialog.Description>
          <div className="flex justify-end gap-2">
            <Dialog.Close asChild>
              <button
                type="button"
                disabled={busy}
                className="h-8 rounded-md border border-border bg-background px-3 text-xs font-medium hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50"
              >
                Cancel
              </button>
            </Dialog.Close>
            <button
              type="button"
              disabled={busy}
              onClick={() => void submit()}
              className="h-8 rounded-md bg-destructive px-3 text-xs font-medium text-destructive-foreground hover:opacity-90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50"
            >
              {busy ? "Deleting..." : "Delete thread"}
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function countDescendants(rootId: string, threads: readonly PluginSidebarThread[]): number {
  const childrenOf = new Map<string, string[]>();
  for (const thread of threads) {
    if (!thread.parentThreadId) continue;
    const siblings = childrenOf.get(thread.parentThreadId);
    if (siblings) siblings.push(thread.id);
    else childrenOf.set(thread.parentThreadId, [thread.id]);
  }
  let count = 0;
  const seen = new Set<string>([rootId]);
  const pending = [rootId];
  while (pending.length > 0) {
    const current = pending.pop()!;
    for (const childId of childrenOf.get(current) ?? []) {
      if (seen.has(childId)) continue;
      seen.add(childId);
      count += 1;
      pending.push(childId);
    }
  }
  return count;
}
