import {
  useEffect,
  useRef,
  useState,
  type MouseEvent as ReactMouseEvent,
} from "react";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  experimental_useSidebarThreadSplit as useSidebarThreadSplit,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import { cn } from "./lib/utils";
import { STATUS_SLOT_CLASS, StatusOrTime } from "./StatusSlot";
import { threadDisplayTitle } from "./inbox";
import { ProjectFavicon } from "./ProjectFavicon";
import { projectIconUrl } from "./project-icons";

/**
 * Search is a separate flat mode. A parked match must not disappear behind
 * the collapsed shelf it belongs to in the normal inbox.
 *
 * The host does not expose its search input to plugins, so focus stays there
 * while the user types. Tab enters this roving list; arrows then move between
 * results, Enter opens one, and Escape asks the host to clear search.
 */
export function SearchResults({
  threads,
  projectNameById,
  projectIconRevision,
  activeThreadId,
  now,
  wokeThreadIds,
  onAcknowledgeWake,
  selectedThreadIds,
  onSelectionClick,
  onNavigate,
}: {
  threads: readonly PluginSidebarThread[];
  projectNameById: ReadonlyMap<string, string>;
  projectIconRevision: number;
  activeThreadId: string | null;
  now: number;
  wokeThreadIds: ReadonlySet<string>;
  onAcknowledgeWake: (threadId: string) => void;
  selectedThreadIds: ReadonlySet<string>;
  onSelectionClick: (
    threadId: string,
    event: ReactMouseEvent<HTMLAnchorElement>,
  ) => boolean;
  onNavigate: () => void;
}) {
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const resultRefs = useRef<Array<HTMLAnchorElement | null>>([]);
  const orderKey = threads.map((thread) => thread.id).join("\0");

  useEffect(() => {
    setHighlightedIndex(0);
  }, [orderKey]);

  const focusResult = (index: number) => {
    setHighlightedIndex(index);
    const result = resultRefs.current[index];
    result?.focus();
    result?.scrollIntoView?.({ block: "nearest" });
  };

  return (
    <ul
      role="listbox"
      aria-label="Thread search results"
      aria-multiselectable="true"
      className="flex flex-col gap-px"
      onKeyDown={(event) => {
        if (event.nativeEvent.isComposing) return;
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          onNavigate();
          return;
        }
        if (threads.length === 0) return;
        if (event.key === "ArrowDown") {
          event.preventDefault();
          focusResult((highlightedIndex + 1) % threads.length);
          return;
        }
        if (event.key === "ArrowUp") {
          event.preventDefault();
          focusResult(
            (highlightedIndex - 1 + threads.length) % threads.length,
          );
          return;
        }
        if (event.key === "Enter") {
          event.preventDefault();
          resultRefs.current[highlightedIndex]?.click();
        }
      }}
    >
      {threads.map((thread, index) => (
        <SearchResultRow
          key={thread.id}
          thread={thread}
          projectName={projectNameById.get(thread.projectId) ?? null}
          projectIconUrl={projectIconUrl(
            thread.projectId,
            projectIconRevision,
          )}
          isActive={thread.id === activeThreadId}
          isHighlighted={highlightedIndex === index}
          isSelected={selectedThreadIds.has(thread.id)}
          now={now}
          isWoke={wokeThreadIds.has(thread.id)}
          anchorRef={(node) => {
            resultRefs.current[index] = node;
          }}
          onHighlight={() => setHighlightedIndex(index)}
          onAcknowledgeWake={() => onAcknowledgeWake(thread.id)}
          onSelectionClick={(event) => onSelectionClick(thread.id, event)}
          onNavigate={onNavigate}
        />
      ))}
    </ul>
  );
}

function SearchResultRow({
  thread,
  projectName,
  projectIconUrl,
  isActive,
  isHighlighted,
  isSelected,
  now,
  isWoke,
  anchorRef,
  onHighlight,
  onAcknowledgeWake,
  onSelectionClick,
  onNavigate,
}: {
  thread: PluginSidebarThread;
  projectName: string | null;
  projectIconUrl: string | null;
  isActive: boolean;
  isHighlighted: boolean;
  isSelected: boolean;
  now: number;
  isWoke: boolean;
  anchorRef: (node: HTMLAnchorElement | null) => void;
  onHighlight: () => void;
  onAcknowledgeWake: () => void;
  onSelectionClick: (event: ReactMouseEvent<HTMLAnchorElement>) => boolean;
  onNavigate: () => void;
}) {
  const actions = useSidebarThreadActions();
  const { splitProps, layout } = useSidebarThreadSplit(thread.id);
  const title = threadDisplayTitle(thread);

  return (
    <li role="presentation" className="list-none">
      <a
        ref={anchorRef}
        id={`bb-sidebar-search-result-${thread.id}`}
        data-sidebar-thread-shortcut-target=""
        data-sidebar-thread-id={thread.id}
        href="#"
        role="option"
        tabIndex={isHighlighted ? 0 : -1}
        aria-selected={isSelected}
        aria-current={isActive ? "page" : undefined}
        data-selected={isSelected ? "true" : undefined}
        aria-label={projectName ? `${title}, ${projectName}` : title}
        {...splitProps}
        onFocus={onHighlight}
        onMouseMove={onHighlight}
        onClick={(event) => {
          event.preventDefault();
          if (onSelectionClick(event)) return;
          if (isWoke) onAcknowledgeWake();
          actions.open(thread.id, { split: false });
          onNavigate();
        }}
        className={cn(
          "flex h-9 items-center gap-2 rounded-md px-2.5 text-sm outline-none transition-colors",
          isHighlighted || isActive
            ? "bg-sidebar-accent text-foreground"
            : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
          isSelected && "ring-1 ring-inset ring-primary/60",
          !isActive && layout !== null && "bg-sidebar-accent/30",
        )}
      >
        <span className="min-w-0 flex-1 truncate">{title}</span>
        {projectName ? (
          <span className="flex max-w-28 shrink-0 items-center gap-1.5 text-2xs text-muted-foreground/70">
            <ProjectFavicon src={projectIconUrl} className="size-3" />
            <span className="min-w-0 truncate">{projectName}</span>
          </span>
        ) : null}
        <span
          className={cn(
            STATUS_SLOT_CLASS,
            isWoke &&
              "justify-end text-2xs font-medium text-amber-700 dark:text-amber-300",
          )}
        >
          {isWoke ? "Woke" : <StatusOrTime thread={thread} now={now} />}
        </span>
      </a>
    </li>
  );
}
