import { useEffect, useRef, useState } from "react";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { cn } from "./lib/utils";
import { threadDisplayTitle } from "./inbox";

/** Inline title editing shared by full cards and parked rows. */
export function InlineThreadTitle({
  thread,
  editing,
  onEditingChange,
  className,
}: {
  thread: PluginSidebarThread;
  editing: boolean;
  onEditingChange: (editing: boolean) => void;
  className?: string;
}) {
  const actions = useSidebarThreadActions();
  const title = threadDisplayTitle(thread);
  const [draft, setDraft] = useState(title);
  const finished = useRef(false);

  useEffect(() => {
    if (!editing) return;
    setDraft(title);
    finished.current = false;
  }, [editing, title]);

  if (!editing) return <span className={className}>{title}</span>;

  const finish = (save: boolean) => {
    if (finished.current) return;
    finished.current = true;
    onEditingChange(false);
    const nextTitle = draft.trim();
    if (save && nextTitle.length > 0 && nextTitle !== title) {
      void actions.rename(thread.id, nextTitle);
    }
  };

  return (
    <input
      autoFocus
      aria-label={`Rename ${title}`}
      value={draft}
      onFocus={(event) => event.currentTarget.select()}
      onChange={(event) => setDraft(event.currentTarget.value)}
      onClick={(event) => event.stopPropagation()}
      onDoubleClick={(event) => event.stopPropagation()}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          finish(true);
        } else if (event.key === "Escape") {
          event.preventDefault();
          finish(false);
        }
      }}
      onBlur={() => finish(true)}
      className={cn(
        "h-6 w-full min-w-0 rounded border border-border bg-background px-1.5 text-inherit text-foreground outline-none focus:ring-1 focus:ring-ring",
        className,
      )}
    />
  );
}
