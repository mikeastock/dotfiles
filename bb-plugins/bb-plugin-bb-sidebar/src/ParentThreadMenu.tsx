import { useEffect, useRef, useState } from "react";
import * as ContextMenu from "@radix-ui/react-context-menu";
import {
  experimental_useSidebarThreads as useSidebarThreads,
  useRpc,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { Icon } from "./components/Icon";
import { threadDisplayTitle } from "./inbox";
import { usePortalScopeProps } from "./lib/portal-scope";
import { parentCandidates } from "./parent-threads";

export function ParentThreadMenu({ thread }: { thread: PluginSidebarThread }) {
  const { projects, threads } = useSidebarThreads();
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const portalScope = usePortalScopeProps();
  const [open, setOpen] = useState(false);
  const searchRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const contentRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    // Focus after Radix finishes moving focus into the submenu.
    const timer = window.setTimeout(() => searchRef.current?.focus(), 0);
    return () => window.clearTimeout(timer);
  }, [open]);
  const projectNameById = new Map(projects.map((project) => [project.id, project.name]));
  // Threads from other projects read as "Project · Thread" and sort after this project's.
  const candidates = parentCandidates(threads, thread)
    .map((candidate) => {
      const isOtherProject = candidate.projectId !== thread.projectId;
      const projectName = isOtherProject
        ? projectNameById.get(candidate.projectId) ?? candidate.projectId
        : null;
      const threadTitle = threadDisplayTitle(candidate);
      return {
        id: candidate.id,
        title: projectName === null ? threadTitle : `${projectName} · ${threadTitle}`,
        projectName,
        threadTitle,
        isPinned: candidate.isPinned,
        isOtherProject,
        updatedAt: candidate.updatedAt,
      };
    })
    .filter((candidate) =>
      candidate.title.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase()),
    )
    .sort((left, right) =>
      Number(left.isOtherProject) - Number(right.isOtherProject) ||
      right.updatedAt - left.updatedAt ||
      left.id.localeCompare(right.id),
    );
  const choices = [
    { id: "", title: "None", projectName: null, threadTitle: "None", isPinned: false },
    ...candidates,
  ];
  const updateParent = async (parentThreadId: string | null) => {
    if (inFlight.current || parentThreadId === thread.parentThreadId) return;
    inFlight.current = true;
    setSaving(true);
    try {
      await rpc.call("setThreadParent", { threadId: thread.id, parentThreadId });
      toast.success(parentThreadId === null ? "Parent removed" : "Parent updated");
    } catch (error) {
      toast.error("Could not update parent", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };
  return (
    <ContextMenu.Sub open={open} onOpenChange={(nextOpen) => {
      setOpen(nextOpen);
      if (nextOpen) setQuery("");
    }}>
      <ContextMenu.SubTrigger
        disabled={saving}
        className="flex cursor-pointer items-center rounded-md px-2 py-1.5 text-sm outline-none data-[state=open]:bg-accent data-[highlighted]:bg-accent data-[disabled]:opacity-50"
      >
        Parent
        <Icon name="ChevronRight" className="ml-auto size-4 opacity-60" />
      </ContextMenu.SubTrigger>
      <ContextMenu.Portal>
        <ContextMenu.SubContent
          {...portalScope}
          ref={contentRef}
          aria-label="Assign parent thread"
          sideOffset={4}
          className="z-50 w-72 max-w-[calc(100vw-2rem)] rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <div className="mb-1 flex items-center gap-2 border-b border-border px-2 py-2">
            <Icon name="Search" className="size-4 shrink-0 text-muted-foreground" />
            <input
              ref={searchRef}
              aria-label="Search parent threads"
              placeholder="Search threads…"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape" || event.key === "Tab") return;
                // Keep menu typeahead and arrow-left navigation out of the input.
                event.stopPropagation();
                if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                  event.preventDefault();
                  const items = contentRef.current?.querySelectorAll<HTMLElement>('[role="menuitemradio"]');
                  const item = event.key === "ArrowDown" ? items?.[0] : items?.[items.length - 1];
                  item?.focus();
                }
              }}
              className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
            />
          </div>
          <ContextMenu.Label className="px-2 py-1 text-xs text-muted-foreground">
            Assign parent thread
          </ContextMenu.Label>
          <ContextMenu.RadioGroup
            value={thread.parentThreadId ?? ""}
            onValueChange={(value) => void updateParent(value || null)}
            className="max-h-64 overflow-y-auto"
          >
            {choices.map((candidate) => (
              <ContextMenu.RadioItem
                key={candidate.id}
                value={candidate.id}
                disabled={saving}
                textValue={candidate.title}
                className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-accent data-[disabled]:opacity-50"
              >
                {candidate.isPinned ? <Icon name="Pin" className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" /> : null}
                <span className="flex-1 truncate">
                  {candidate.projectName === null ? null : (
                    <><span className="font-semibold">{candidate.projectName}</span> · </>
                  )}
                  {candidate.threadTitle}
                </span>
                <ContextMenu.ItemIndicator><Icon name="Check" className="size-4" /></ContextMenu.ItemIndicator>
              </ContextMenu.RadioItem>
            ))}
          </ContextMenu.RadioGroup>
          {candidates.length === 0 ? (
            <div className="px-2 py-2 text-xs text-muted-foreground">No matching threads</div>
          ) : null}
        </ContextMenu.SubContent>
      </ContextMenu.Portal>
    </ContextMenu.Sub>
  );
}
