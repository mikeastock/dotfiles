import type { ReactNode } from "react";
import * as ContextMenu from "@radix-ui/react-context-menu";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  experimental_useSidebarThreadSplit as useSidebarThreadSplit,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import { resolveSnoozePresets } from "./lifecycle";
import { TOUCH_TARGET_CLASS, useIsCompactViewport } from "./useCompactViewport";

/**
 * The park actions a row offers, which differ by where the row sits: an inbox
 * card can be parked, a shelved row can only come back. `null` covers a card
 * that may not be parked at all, because the thread is still working.
 */
export type RowLifecycle =
  | {
      kind: "park";
      onSnooze: (snoozedUntil: number) => void;
      onSettle: () => void;
    }
  | { kind: "restore"; shelf: "snoozed" | "settled"; onRestore: () => void }
  | null;

type MenuEntry =
  | { kind: "separator"; key: string }
  | { kind: "label"; key: string; text: string }
  | {
      kind: "item";
      key: string;
      label: string;
      destructive?: boolean;
      onSelect: () => void;
    };

/**
 * Every action a row offers, in one list.
 *
 * The park actions live here as well as on the row because a coarse pointer
 * has no hover to reveal them with — this menu is the only way to reach them
 * on a phone, and it is a fair second route on a desktop.
 *
 * Called from inside the menu's content, which Radix mounts on open, so the
 * snooze presets are resolved against the time the user opened the menu
 * rather than the time the row last rendered.
 */
function useRowMenuEntries(
  thread: PluginSidebarThread,
  lifecycle: RowLifecycle,
): MenuEntry[] {
  const actions = useSidebarThreadActions();
  // False on compact viewports and when the user turned splits off, so this
  // is the flag that decides whether an "open in split" item is honest.
  const { isAvailable: canSplit } = useSidebarThreadSplit(thread.id);

  const entries: MenuEntry[] = [];

  if (lifecycle?.kind === "park") {
    entries.push({ kind: "label", key: "snooze-label", text: "Snooze" });
    for (const preset of resolveSnoozePresets(new Date())) {
      entries.push({
        kind: "item",
        key: `snooze-${preset.id}`,
        label: preset.label,
        onSelect: () => lifecycle.onSnooze(preset.snoozedUntil),
      });
    }
    entries.push({
      kind: "item",
      key: "settle",
      label: "Settle",
      onSelect: lifecycle.onSettle,
    });
    entries.push({ kind: "separator", key: "after-park" });
  }

  if (lifecycle?.kind === "restore") {
    entries.push({
      kind: "item",
      key: "restore",
      label: lifecycle.shelf === "snoozed" ? "Wake now" : "Un-settle",
      onSelect: lifecycle.onRestore,
    });
    entries.push({ kind: "separator", key: "after-restore" });
  }

  if (canSplit) {
    entries.push({
      kind: "item",
      key: "split",
      label: "Open in split",
      onSelect: () => actions.open(thread.id, { split: true }),
    });
    entries.push({ kind: "separator", key: "after-split" });
  }

  entries.push({
    kind: "item",
    key: "read",
    label: thread.isUnread ? "Mark read" : "Mark unread",
    onSelect: () => void actions.setRead(thread.id, thread.isUnread),
  });
  entries.push({
    kind: "item",
    key: "pin",
    label: thread.isPinned ? "Unpin" : "Pin",
    onSelect: () => void actions.setPinned(thread.id, !thread.isPinned),
  });
  entries.push({ kind: "separator", key: "before-destructive" });
  entries.push({
    kind: "item",
    key: "archive",
    label: "Archive",
    onSelect: () => actions.archive(thread.id),
  });
  entries.push({
    kind: "item",
    key: "delete",
    label: "Delete",
    destructive: true,
    // `requestDelete`, not a delete: this opens BB's confirmation rather than
    // removing a subtree silently.
    onSelect: () => actions.requestDelete(thread.id),
  });

  return entries;
}

const CONTENT_CLASS =
  "z-50 min-w-44 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md";

function itemClass(destructive: boolean, isCompact: boolean): string {
  return cn(
    "cursor-pointer rounded-md px-2 text-sm outline-none",
    // A menu row is the whole tap target on a phone, so it carries the 44px
    // itself instead of borrowing a pseudo-element.
    isCompact ? "py-2.5" : "py-1.5",
    "data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground",
    destructive && "text-destructive-text",
  );
}

function labelClass(isCompact: boolean): string {
  return cn(
    "px-2 text-2xs font-medium text-muted-foreground",
    isCompact ? "py-1.5" : "py-1",
  );
}

/**
 * This sidebar's own right-click menu, and — because Radix opens the same
 * trigger on a 700ms press — its touch menu.
 *
 * The plugin API ships no menu component on purpose, so a replaced sidebar
 * owns this surface.
 */
export function RowContextMenu({
  thread,
  lifecycle,
  children,
}: {
  thread: PluginSidebarThread;
  lifecycle: RowLifecycle;
  children: ReactNode;
}) {
  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>{children}</ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content
          aria-label="Thread actions"
          className={CONTENT_CLASS}
        >
          <ContextMenuEntries thread={thread} lifecycle={lifecycle} />
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}

function ContextMenuEntries({
  thread,
  lifecycle,
}: {
  thread: PluginSidebarThread;
  lifecycle: RowLifecycle;
}) {
  const isCompact = useIsCompactViewport();
  const entries = useRowMenuEntries(thread, lifecycle);

  return (
    <>
      {entries.map((entry) =>
        entry.kind === "separator" ? (
          <ContextMenu.Separator
            key={entry.key}
            className="my-1 h-px bg-border"
          />
        ) : entry.kind === "label" ? (
          <ContextMenu.Label key={entry.key} className={labelClass(isCompact)}>
            {entry.text}
          </ContextMenu.Label>
        ) : (
          <ContextMenu.Item
            key={entry.key}
            onSelect={entry.onSelect}
            className={itemClass(entry.destructive ?? false, isCompact)}
          >
            {entry.label}
          </ContextMenu.Item>
        ),
      )}
    </>
  );
}

/**
 * The same menu behind a visible button, drawn on compact viewports only.
 *
 * Long-press reaches the context menu on a touch screen, but nothing on the
 * row says so. This is the affordance: one control per row, wide enough to
 * hit, in place of the hover-revealed actions a phone can never show.
 */
export function RowMenuButton({
  thread,
  lifecycle,
}: {
  thread: PluginSidebarThread;
  lifecycle: RowLifecycle;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label="Thread actions"
          // The row's full-bleed anchor sits underneath every control, so a
          // press that lands here must not also open the thread.
          onClick={(event) => {
            event.preventDefault();
            event.stopPropagation();
          }}
          className={cn(
            "pointer-events-auto relative flex size-5 shrink-0 items-center justify-center rounded text-muted-foreground",
            TOUCH_TARGET_CLASS,
          )}
        >
          <Icon name="More" className="size-3.5" aria-hidden />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={4}
          aria-label="Thread actions"
          className={CONTENT_CLASS}
        >
          <DropdownMenuEntries thread={thread} lifecycle={lifecycle} />
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

function DropdownMenuEntries({
  thread,
  lifecycle,
}: {
  thread: PluginSidebarThread;
  lifecycle: RowLifecycle;
}) {
  const isCompact = useIsCompactViewport();
  const entries = useRowMenuEntries(thread, lifecycle);

  return (
    <>
      {entries.map((entry) =>
        entry.kind === "separator" ? (
          <DropdownMenu.Separator
            key={entry.key}
            className="my-1 h-px bg-border"
          />
        ) : entry.kind === "label" ? (
          <DropdownMenu.Label key={entry.key} className={labelClass(isCompact)}>
            {entry.text}
          </DropdownMenu.Label>
        ) : (
          <DropdownMenu.Item
            key={entry.key}
            onSelect={entry.onSelect}
            className={itemClass(entry.destructive ?? false, isCompact)}
          >
            {entry.label}
          </DropdownMenu.Item>
        ),
      )}
    </>
  );
}
