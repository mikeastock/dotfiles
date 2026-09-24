import type { ReactNode } from "react";
import * as ContextMenu from "@radix-ui/react-context-menu";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import type { ConfiguredSnoozePreset } from "./lifecycle";

/**
 * This sidebar's own right-click menu.
 *
 * The plugin API ships no menu component on purpose, so a replaced sidebar
 * owns this surface. Every item below is one call on
 * `experimental_useSidebarThreadActions`, and the destructive one is
 * `requestDelete`, which opens BB's confirmation rather than deleting a
 * subtree silently.
 */
export function RowContextMenu({
  thread,
  children,
  canSnooze = false,
  canArchive = true,
  snoozePresets = [],
  onSnooze,
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
  onSettle?: () => void;
  onUnsettle?: () => void;
  onWake?: () => void;
  onRename?: () => void;
}) {
  const actions = useSidebarThreadActions();

  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>{children}</ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content
          aria-label="Thread actions"
          className="z-50 min-w-44 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <Item onSelect={() => actions.open(thread.id, { split: true })}>
            Open in split
          </Item>
          <Separator />
          <Item
            onSelect={() => void actions.setPinned(thread.id, !thread.isPinned)}
          >
            {thread.isPinned ? "Unpin" : "Pin"}
          </Item>
          {onSettle ? <Item onSelect={onSettle}>Settle</Item> : null}
          {onUnsettle ? <Item onSelect={onUnsettle}>Un-settle</Item> : null}
          {canSnooze && onSnooze && snoozePresets.length > 0 ? (
            <SnoozeSubmenu presets={snoozePresets} onSnooze={onSnooze} />
          ) : null}
          {onWake ? <Item onSelect={onWake}>Wake now</Item> : null}
          <Separator />
          {onRename ? (
            <Item onSelect={() => globalThis.setTimeout(onRename, 0)}>
              Rename
            </Item>
          ) : null}
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
            onSelect={() => actions.archive(thread.id)}
          >
            Archive
          </Item>
          <Item destructive onSelect={() => actions.requestDelete(thread.id)}>
            Delete
          </Item>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}

function CopySubmenu({ thread }: { thread: PluginSidebarThread }) {
  const branchName = thread.environment?.branchName;
  const copy = (text: string) => {
    if (typeof navigator === "undefined" || !navigator.clipboard) return;
    void navigator.clipboard.writeText(text);
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
          aria-label="Copy thread data"
          sideOffset={4}
          className="z-50 min-w-40 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
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
  return (
    <ContextMenu.Sub>
      <ContextMenu.SubTrigger
        className={cn(
          "flex cursor-pointer items-center rounded-md px-2 py-1.5 text-sm outline-none",
          "data-[state=open]:bg-accent data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
        )}
      >
        Snooze
        <Icon name="ChevronRight" className="ml-auto size-4 opacity-60" />
      </ContextMenu.SubTrigger>
      <ContextMenu.Portal>
        <ContextMenu.SubContent
          aria-label="Snooze times"
          sideOffset={4}
          className="z-50 min-w-40 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          {presets.map((preset) => (
            <Item
              key={preset.id}
              onSelect={() => onSnooze(Date.now() + preset.durationMs)}
            >
              {preset.label}
            </Item>
          ))}
        </ContextMenu.SubContent>
      </ContextMenu.Portal>
    </ContextMenu.Sub>
  );
}

function Item({
  children,
  destructive = false,
  disabled = false,
  onSelect,
}: {
  children: ReactNode;
  destructive?: boolean;
  disabled?: boolean;
  onSelect: () => void;
}) {
  return (
    <ContextMenu.Item
      disabled={disabled}
      onSelect={onSelect}
      className={cn(
        "cursor-pointer rounded-md px-2 py-1.5 text-sm outline-none",
        "data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
        "data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50",
        destructive && "text-destructive-text",
      )}
    >
      {children}
    </ContextMenu.Item>
  );
}

function Separator() {
  return <ContextMenu.Separator className="my-1 h-px bg-border" />;
}
