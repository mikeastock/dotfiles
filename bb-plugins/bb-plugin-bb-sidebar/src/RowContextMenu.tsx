import { useRef, useState, type ReactNode } from "react";
import * as ContextMenu from "@radix-ui/react-context-menu";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  experimental_useSidebarThreads as useSidebarThreads,
  useRpc,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { ParentThreadMenu } from "./ParentThreadMenu";
import { DeleteThreadDialog } from "./DeleteThreadDialog";
import { Icon, type IconName } from "./components/Icon";
import { cn } from "./lib/utils";
import { usePortalScopeProps } from "./lib/portal-scope";
import { ProjectActions } from "./ProjectContextMenu";
import {
  canParkThread,
  formatSnoozeWakeTime,
  resolveConfiguredSnoozePreset,
  type ConfiguredSnoozePreset,
} from "./lifecycle";
import { beginTitleGeneration, finishTitleGeneration, useTitleGenerating } from "./title-generation-state";

/**
 * This sidebar's own right-click menu.
 *
 * The plugin API ships no menu component on purpose, so a replaced sidebar
 * owns this surface. Native actions use
 * `experimental_useSidebarThreadActions`. The destructive one goes through
 * this sidebar's own confirmation, which names the thread and project, and
 * then the plugin's `deleteThread` rpc; nothing deletes a subtree silently.
 */
export function RowContextMenu({
  thread,
  children,
  canSnooze = false,
  canArchive = true,
  snoozePresets = [],
  onSnooze,
  onPark,
  onResume,
  onSettle,
  onUnsettle,
  onWake,
  onRename,
}: {
  thread: PluginSidebarThread;
  children: ReactNode;
  canSnooze?: boolean;
  canArchive?: boolean;
  snoozePresets?: readonly ConfiguredSnoozePreset[];
  onSnooze?: (snoozedUntil: number) => void;
  onPark?: () => void;
  onResume?: () => void;
  onSettle?: () => void;
  onUnsettle?: () => void;
  onWake?: () => void;
  onRename?: () => void;
}) {
  const actions = useSidebarThreadActions();
  const { projects, threads } = useSidebarThreads();
  const project = projects.find((project) => project.id === thread.projectId);
  const portalScope = usePortalScopeProps();
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const regenerating = useTitleGenerating(thread.id);
  const renameAfterClose = useRef(false);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  // Archive takes the children with it, and bb leaves every idle one's agent
  // session loaded. Release them alongside the archive. Working children are
  // skipped, so this never interrupts a turn archive itself would not.
  const archive = () => {
    actions.archive(thread.id);
    const threadIds = [
      thread.id,
      ...threads
        .filter(
          (child) =>
            child.parentThreadId === thread.id && canParkThread(child),
        )
        .map((child) => child.id),
    ];
    void rpc.call("releaseRuntimes", { threadIds }).catch(() => {
      void 0; // A missed release costs memory, not correctness.
    });
  };
  const regenerate = async () => {
    if (!beginTitleGeneration(thread.id)) return;
    try {
      await rpc.call("regenerateTitle", { threadId: thread.id });
      toast.success("Thread title regenerated");
    } catch (error) {
      toast.error("Could not regenerate title", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      finishTitleGeneration(thread.id);
    }
  };
  const togglePin = async () => {
    try {
      if (thread.isPinned) {
        await actions.setPinned(thread.id, false);
      } else {
        await rpc.call("pin", { threadId: thread.id });
      }
    } catch (error) {
      toast.error(thread.isPinned ? "Could not unpin thread" : "Could not pin thread", {
        description: error instanceof Error ? error.message : undefined,
      });
    }
  };

  return (
    <>
    <ProjectActions project={project}>
    {({ items: projectItems, onOpenChange, onCloseAutoFocus }) => (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>{children}</ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content
          {...portalScope}
          aria-label="Thread actions"
          onCloseAutoFocus={(event) => {
            onCloseAutoFocus?.(event);
            // The delete dialog takes focus next; do not pull it back to the row.
            if (confirmingDelete) event.preventDefault();
            if (!renameAfterClose.current) return;
            renameAfterClose.current = false;
            // Hand focus to the editor after the menu releases its focus scope.
            event.preventDefault();
            onRename?.();
          }}
          className="z-50 min-w-44 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <Item onSelect={() => actions.open(thread.id, { split: true })}>
            Open in split
          </Item>
          <ParentThreadMenu thread={thread} />
          {projectItems ? (
            <ContextMenu.Sub onOpenChange={onOpenChange}>
              <ContextMenu.SubTrigger className="flex cursor-pointer items-center rounded-md px-2 py-1.5 text-sm outline-none data-[state=open]:bg-accent data-[highlighted]:bg-accent">
                Project
                <Icon name="ChevronRight" className="ml-auto size-4 opacity-60" />
              </ContextMenu.SubTrigger>
              <ContextMenu.Portal>
                <ContextMenu.SubContent {...portalScope} aria-label="Project actions" sideOffset={4}
                  className="z-50 min-w-44 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md">
                  <ContextMenu.Label className="max-w-64 truncate px-2 py-1 text-xs text-muted-foreground">{project?.name}</ContextMenu.Label>
                  {projectItems}
                </ContextMenu.SubContent>
              </ContextMenu.Portal>
            </ContextMenu.Sub>
          ) : null}
          <Separator />
          <Item icon={thread.isPinned ? "PinOff" : "Pin"} onSelect={() => void togglePin()}>
            {thread.isPinned ? "Unpin" : "Pin"}
          </Item>
          {onPark ? <Item icon="Car" onSelect={onPark}>Park thread</Item> : null}
          {onResume ? <Item icon="Pulse" onSelect={onResume}>Resume</Item> : null}
          {onSettle ? <Item icon="Meditation" onSelect={onSettle}>Settle</Item> : null}
          {onUnsettle ? <Item icon="Pulse" onSelect={onUnsettle}>Un-settle</Item> : null}
          {canSnooze && onSnooze && snoozePresets.length > 0 ? (
            <SnoozeSubmenu presets={snoozePresets} onSnooze={onSnooze} />
          ) : null}
          {onWake ? <Item icon="Pulse" onSelect={onWake}>Wake now</Item> : null}
          <Separator />
          {onRename ? (
            <Item onSelect={() => { renameAfterClose.current = true; }}>
              Rename
            </Item>
          ) : null}
          <Item disabled={regenerating} onSelect={() => void regenerate()}>
            {regenerating ? "Regenerating title…" : "Regenerate title"}
          </Item>
          <Item
            onSelect={() => void actions.setRead(thread.id, thread.isUnread)}
          >
            {thread.isUnread ? "Mark read" : "Mark unread"}
          </Item>
          <Separator />
          <CopySubmenu thread={thread} />
          <Separator />
          <Item
            disabled={!canArchive}
            onSelect={archive}
          >
            Archive
          </Item>
          <Item destructive onSelect={() => setConfirmingDelete(true)}>
            Delete
          </Item>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
    )}
    </ProjectActions>
    <DeleteThreadDialog thread={thread} open={confirmingDelete} onOpenChange={setConfirmingDelete} />
    </>
  );
}

function CopySubmenu({ thread }: { thread: PluginSidebarThread }) {
  const { projects } = useSidebarThreads();
  const portalScope = usePortalScopeProps();
  const branchName = thread.environment?.branchName;
  const copy = (text: string) => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    void navigator.clipboard.writeText(text);
  };
  const copyThreadLink = async () => {
    const isPersonal = projects.some(
      (project) => project.id === thread.projectId && project.isPersonal,
    );
    const threadPath = `/threads/${encodeURIComponent(thread.id)}`;
    const path = isPersonal
      ? threadPath
      : `/projects/${encodeURIComponent(thread.projectId)}${threadPath}`;
    try {
      await navigator.clipboard.writeText(new URL(path, window.location.origin).href);
      toast.success("Thread link copied");
    } catch {
      toast.error("Failed to copy thread link");
    }
  };

  return (
    <ContextMenu.Sub>
      <ContextMenu.SubTrigger
        className={cn(
          "flex cursor-pointer items-center rounded-md px-2 py-1.5 text-sm outline-none",
          "data-[state=open]:bg-accent data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
        )}
      >
        Copy
        <Icon name="ChevronRight" className="ml-auto size-4 opacity-60" />
      </ContextMenu.SubTrigger>
      <ContextMenu.Portal>
        <ContextMenu.SubContent
          {...portalScope}
          aria-label="Copy thread data"
          sideOffset={4}
          className="z-50 min-w-40 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <Item onSelect={() => void copyThreadLink()}>Copy thread link</Item>
          {branchName ? (
            <Item onSelect={() => copy(branchName)}>
              Copy branch
            </Item>
          ) : null}
          <Item onSelect={() => copy(thread.id)}>Copy thread ID</Item>
        </ContextMenu.SubContent>
      </ContextMenu.Portal>
    </ContextMenu.Sub>
  );
}

function SnoozeSubmenu({
  presets,
  onSnooze,
}: {
  presets: readonly ConfiguredSnoozePreset[];
  onSnooze: (snoozedUntil: number) => void;
}) {
  const portalScope = usePortalScopeProps();
  return (
    <ContextMenu.Sub>
      <ContextMenu.SubTrigger
        className={cn(
          "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none",
          "data-[state=open]:bg-accent data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
        )}
      >
        <Icon name="Clock" className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
        Snooze
        <Icon name="ChevronRight" className="ml-auto size-4 opacity-60" />
      </ContextMenu.SubTrigger>
      <ContextMenu.Portal>
        <ContextMenu.SubContent
          {...portalScope}
          aria-label="Snooze times"
          sideOffset={4}
          className="z-50 min-w-40 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          {presets.map((preset) => {
            const wake = resolveConfiguredSnoozePreset(preset);
            return (
              <Item
                key={preset.id}
                disabled={wake === null}
                title={wake === null ? "Today's time has passed" : formatSnoozeWakeTime(wake)}
                onSelect={() => {
                  const selectedWake = resolveConfiguredSnoozePreset(preset);
                  if (selectedWake !== null) onSnooze(selectedWake);
                }}
              >
                {preset.label}
              </Item>
            );
          })}
        </ContextMenu.SubContent>
      </ContextMenu.Portal>
    </ContextMenu.Sub>
  );
}

function Item({
  children,
  icon,
  destructive = false,
  disabled = false,
  title,
  onSelect,
}: {
  children: ReactNode;
  icon?: IconName;
  destructive?: boolean;
  disabled?: boolean;
  title?: string;
  onSelect: () => void;
}) {
  return (
    <ContextMenu.Item
      disabled={disabled}
      title={title}
      onSelect={onSelect}
      className={cn(
        "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none",
        "data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
        "data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50",
        destructive && "text-destructive-text",
      )}
    >
      {icon ? <Icon name={icon} className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" /> : null}
      {children}
    </ContextMenu.Item>
  );
}

function Separator() {
  return <ContextMenu.Separator className="my-1 h-px bg-border" />;
}
