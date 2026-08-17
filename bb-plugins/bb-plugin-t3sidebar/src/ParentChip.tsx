import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  experimental_useSidebarThreads as useSidebarThreads,
  type PluginThreadHeaderActionProps,
} from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import { Disc } from "./Disc";
import { parentOf, threadDisplayTitle } from "./inbox";
import { TOUCH_TARGET_CLASS } from "./useCompactViewport";

/**
 * The way back out of a child thread.
 *
 * The child's row nests under its parent but cannot open it — the row belongs
 * to the child, and a second link inside it would fight the full-bleed anchor.
 * This chip is the one that navigates. The disc repeats the parent's colour
 * from the list, so the chip points at a thread the user can recognise.
 */
export function ParentChip({
  threadId,
  isCompactViewport,
}: PluginThreadHeaderActionProps) {
  const { threads } = useSidebarThreads();
  const actions = useSidebarThreadActions();

  const parent = parentOf(threads, threadId);
  if (parent === null) return null;

  const title = threadDisplayTitle(parent);

  return (
    <button
      type="button"
      aria-label={`Back to parent: ${title}`}
      title={title}
      onClick={() => actions.open(parent.id)}
      className={cn(
        "relative flex h-7 max-w-full cursor-pointer items-center gap-1.5 rounded-full border border-border text-2xs text-muted-foreground",
        "hover:bg-accent hover:text-foreground",
        // Icon-only on a short header row, per the slot's own guidance — so
        // the press has to reach past the chip's 28px without the header
        // growing to match.
        isCompactViewport ? `px-1.5 ${TOUCH_TARGET_CLASS}` : "px-2",
      )}
    >
      <Icon name="ChevronLeft" className="size-3 shrink-0" aria-hidden />
      <Disc thread={parent} />
      {isCompactViewport ? null : <span className="truncate">{title}</span>}
    </button>
  );
}
