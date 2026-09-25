import {
  useEffect,
  useRef,
  useState,
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
import { ThreadTitle } from "./ThreadTitle";
import { OpenPortsIndicator } from "./OpenPorts";

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
  onNavigate,
}: {
  threads: readonly PluginSidebarThread[];
  projectNameById: ReadonlyMap<string, string>;
  projectIconRevision: number;
  activeThreadId: string | null;
  now: number;
  wokeThreadIds: ReadonlySet<string>;
  onAcknowledgeWake: (threadId: string) => void;
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
          now={now}
          isWoke={wokeThreadIds.has(thread.id)}
          anchorRef={(node) => {
            resultRefs.current[index] = node;
          }}
          onHighlight={() => setHighlightedIndex(index)}
          onAcknowledgeWake={() => onAcknowledgeWake(thread.id)}
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
  now,
  isWoke,
  anchorRef,
  onHighlight,
  onAcknowledgeWake,
  onNavigate,
}: {
  thread: PluginSidebarThread;
  projectName: string | null;
  projectIconUrl: string | null;
  isActive: boolean;
  isHighlighted: boolean;
  now: number;
  isWoke: boolean;
  anchorRef: (node: HTMLAnchorElement | null) => void;
  onHighlight: () => void;
  onAcknowledgeWake: () => void;
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
        aria-selected={isHighlighted}
        aria-current={isActive ? "page" : undefined}
        aria-label={projectName ? `${title}, ${projectName}` : title}
        {...splitProps}
        onFocus={onHighlight}
        onMouseMove={onHighlight}
        onClick={(event) => {
          event.preventDefault();
          if (isWoke) onAcknowledgeWake();
          actions.open(thread.id, { split: false });
          onNavigate();
        }}
        className={cn(
          "rounded-md px-2.5 text-sm outline-none transition-colors",
          isWoke
            ? "grid h-11 grid-cols-[minmax(0,1fr)_auto] grid-rows-2 items-center gap-x-2"
            : "flex h-9 items-center gap-2",
          isHighlighted || isActive
            ? "bg-sidebar-accent text-foreground"
            : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
          !isActive && layout !== null && "bg-sidebar-accent/30",
        )}
      >
        <span className="flex min-w-0 flex-1 items-center gap-1.5">
          <ThreadTitle threadId={thread.id} title={title} className="min-w-0 flex-1 truncate" />
          <OpenPortsIndicator thread={thread} />
        </span>
        {projectName ? (
          <span
            className={cn(
              "flex min-w-0 items-center gap-1.5 text-2xs text-muted-foreground/70",
              isWoke
                ? "col-start-1 row-start-2 max-w-full"
                : // Proportional rather than a fixed 112px: on one line the
                  // project shares the row with the title and the status
                  // slot, and at a 280px sidebar a fixed cap left the title
                  // about six characters. The title is what the user searched
                  // for, so the project yields first.
                  "max-w-[30%] shrink-0",
            )}
          >
            <ProjectFavicon src={projectIconUrl} className="size-3" />
            <span className="min-w-0 truncate">{projectName}</span>
          </span>
        ) : null}
        <span
          className={cn(
            STATUS_SLOT_CLASS,
            isWoke && "col-start-2 row-span-2 row-start-1 w-auto gap-1",
          )}
        >
          {isWoke ? (
            <span className="shrink-0 text-2xs font-medium text-[color:var(--bb-sidebar-woke)]">
              Woke
            </span>
          ) : null}
          <StatusOrTime thread={thread} now={now} />
        </span>
      </a>
    </li>
  );
}
