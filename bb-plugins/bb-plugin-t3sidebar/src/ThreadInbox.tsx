import { useEffect, useMemo, useState } from "react";
import {
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  experimental_useSidebarThreads as useSidebarThreads,
  type PluginSidebarThread,
  type PluginThreadListProps,
} from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./components/Select";
import { ThreadCard } from "./ThreadCard";
import { SlimRow } from "./SlimRow";
import { useLifecycle } from "./useLifecycle";
import { TRAILING_GLYPH_BOX_CLASS } from "./StatusSlot";
import {
  CompactViewportProvider,
  useIsCompactViewport,
} from "./useCompactViewport";
import { buildThreadTree, summarizeDescendants, visibleRows } from "./tree";
import { useCollapsedThreads } from "./useCollapsedThreads";
import {
  filterByProject,
  parentTitlesByThreadId,
  partitionPinned,
  searchThreadsByTitle,
  sortByCreatedAtDescending,
  visibleInboxThreads,
} from "./inbox";

const ALL_PROJECTS = "__all__";

/**
 * The sidebar's scrolling list: a statically ordered stack of cards, with
 * children nested under the thread that spawned them.
 *
 * The host owns the New-thread button and the search field above it, so this
 * ships neither. It filters by the `searchQuery` prop and keeps only the one
 * control the host has no equivalent for: the project scope picker.
 */
export function ThreadInbox({
  activeThreadId,
  isCompactViewport,
  onNavigate,
  searchQuery,
}: PluginThreadListProps) {
  const { status, threads, projects } = useSidebarThreads();
  const actions = useSidebarThreadActions();
  const lifecycle = useLifecycle(threads);
  const { collapsed, toggle } = useCollapsedThreads();
  const [scope, setScope] = useState<string>(ALL_PROJECTS);
  // One clock for every card in a render, quantized to the minute so the
  // labels do not disagree and do not churn on unrelated re-renders.
  const [nowMinute, setNowMinute] = useState(() =>
    Math.floor(Date.now() / 60_000),
  );
  useEffect(() => {
    const timer = setInterval(
      () => setNowMinute(Math.floor(Date.now() / 60_000)),
      60_000,
    );
    return () => clearInterval(timer);
  }, []);
  const now = nowMinute * 60_000;
  const [showSnoozed, setShowSnoozed] = useState(false);
  const [showSettled, setShowSettled] = useState(false);

  const projectNameById = useMemo(
    () => new Map(projects.map((project) => [project.id, project.name])),
    [projects],
  );

  // Off the unfiltered list on purpose: a child still names its parent when
  // the project scope, a search, or the archive has taken the parent's row.
  const parentTitleByThreadId = useMemo(
    () => parentTitlesByThreadId(threads),
    [threads],
  );

  const { pinned, inbox, snoozed, settled } = useMemo(() => {
    const scoped = filterByProject(
      visibleInboxThreads(threads),
      scope === ALL_PROJECTS ? null : scope,
    );
    const matched = searchThreadsByTitle(scoped, searchQuery);
    const active: typeof matched = [];
    const onSnoozeShelf: typeof matched = [];
    const onSettledShelf: typeof matched = [];
    for (const thread of matched) {
      const shelf = lifecycle.shelfFor(thread);
      if (shelf === "snoozed") onSnoozeShelf.push(thread);
      else if (shelf === "settled") onSettledShelf.push(thread);
      else active.push(thread);
    }
    const split = partitionPinned(active);
    // One tree per shelf, not one for the whole list: a child whose parent
    // sits on a different shelf has no parent HERE, so the promotion rule
    // gives it a row of its own rather than hiding it under something the
    // shelf does not contain.
    return {
      pinned: buildThreadTree(split.pinned),
      inbox: buildThreadTree(split.inbox),
      // Soonest wake first: "what comes back next" is the shelf's question.
      snoozed: [...onSnoozeShelf].sort(
        (left, right) =>
          (lifecycle.wakeAtFor(left) ?? 0) - (lifecycle.wakeAtFor(right) ?? 0),
      ),
      settled: sortByCreatedAtDescending(onSettledShelf),
    };
  }, [lifecycle, scope, searchQuery, threads]);

  const scopeLabel =
    scope === ALL_PROJECTS
      ? "All projects"
      : (projectNameById.get(scope) ?? "All projects");

  return (
    <CompactViewportProvider value={isCompactViewport}>
      <div className="flex min-h-0 flex-1 flex-col">
        {/* The one control the host has no equivalent for. Everything else in
          the chrome above — New thread, search — is bb's and stays bb's. */}
        <div className="flex shrink-0 items-center gap-1 px-2 pb-1">
          <Select value={scope} onValueChange={setScope}>
            {/* Ghost trigger: no border, no filled track — it reads as a label
              until you hover it. */}
            <SelectTrigger
              className={cn(
                "min-w-0 flex-1 cursor-pointer border-0 px-1.5 py-1 text-xs font-medium text-muted-foreground shadow-none hover:bg-sidebar-accent focus:ring-0",
                // The trigger is a real row of chrome rather than an icon in a
                // dense line, so it takes the 44px in the layout.
                isCompactViewport ? "h-11" : "h-7",
              )}
              aria-label={`Project scope: ${scopeLabel}`}
            >
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={ALL_PROJECTS} className="text-xs">
                All projects
              </SelectItem>
              {projects.map((project) => (
                <SelectItem
                  key={project.id}
                  value={project.id}
                  className="text-xs"
                >
                  {project.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-1.5 pb-2">
          {status === "loading" ? null : status === "error" ? (
            <p
              role="status"
              className="px-2 py-6 text-center text-xs text-muted-foreground"
            >
              Could not load threads.
            </p>
          ) : pinned.length + inbox.length + snoozed.length + settled.length ===
            0 ? (
            <p
              role="status"
              className="px-2 py-6 text-center text-xs text-muted-foreground"
            >
              {searchQuery.trim() ? "No threads found" : "No threads yet"}
            </p>
          ) : (
            <>
              {pinned.length > 0 ? (
                <Shelf label="Pinned">
                  {visibleRows(pinned, collapsed).map((node) => (
                    <ThreadCard
                      key={node.thread.id}
                      thread={node.thread}
                      projectName={
                        projectNameById.get(node.thread.projectId) ?? null
                      }
                      parentTitle={
                        node.depth === 0
                          ? (parentTitleByThreadId.get(node.thread.id) ?? null)
                          : null
                      }
                      depth={node.depth}
                      subtree={
                        node.children.length === 0
                          ? null
                          : summarizeDescendants(node)
                      }
                      isCollapsed={collapsed.has(node.thread.id)}
                      onToggleCollapsed={() => toggle(node.thread.id)}
                      isActive={node.thread.id === activeThreadId}
                      canPark={lifecycle.canPark(node.thread)}
                      onNavigate={onNavigate}
                      onSettle={() => lifecycle.settle(node.thread.id)}
                      onSnooze={(until) =>
                        lifecycle.snooze(node.thread.id, until)
                      }
                      now={now}
                    />
                  ))}
                </Shelf>
              ) : null}
              {inbox.length > 0 ? (
                <Shelf label={pinned.length > 0 ? "Inbox" : null}>
                  {visibleRows(inbox, collapsed).map((node) => (
                    <ThreadCard
                      key={node.thread.id}
                      thread={node.thread}
                      projectName={
                        projectNameById.get(node.thread.projectId) ?? null
                      }
                      parentTitle={
                        node.depth === 0
                          ? (parentTitleByThreadId.get(node.thread.id) ?? null)
                          : null
                      }
                      depth={node.depth}
                      subtree={
                        node.children.length === 0
                          ? null
                          : summarizeDescendants(node)
                      }
                      isCollapsed={collapsed.has(node.thread.id)}
                      onToggleCollapsed={() => toggle(node.thread.id)}
                      isActive={node.thread.id === activeThreadId}
                      canPark={lifecycle.canPark(node.thread)}
                      onNavigate={onNavigate}
                      onSettle={() => lifecycle.settle(node.thread.id)}
                      onSnooze={(until) =>
                        lifecycle.snooze(node.thread.id, until)
                      }
                      now={now}
                    />
                  ))}
                </Shelf>
              ) : null}
              <ParkedShelf
                label="Snoozed"
                threads={snoozed}
                expanded={showSnoozed}
                onToggle={() => setShowSnoozed((open) => !open)}
                shelf="snoozed"
                activeThreadId={activeThreadId}
                lifecycle={lifecycle}
                onNavigate={onNavigate}
              />
              <ParkedShelf
                label="Settled"
                threads={settled}
                expanded={showSettled}
                onToggle={() => setShowSettled((open) => !open)}
                shelf="settled"
                activeThreadId={activeThreadId}
                lifecycle={lifecycle}
                onNavigate={onNavigate}
              />
            </>
          )}
        </div>
      </div>
    </CompactViewportProvider>
  );
}

/**
 * A collapsed shelf of parked threads. The header stays while anything is
 * parked — the count is the whole footprint when collapsed — and the shelf
 * vanishes entirely at zero.
 */
function ParkedShelf({
  label,
  threads,
  expanded,
  onToggle,
  shelf,
  activeThreadId,
  lifecycle,
  onNavigate,
}: {
  label: string;
  threads: readonly PluginSidebarThread[];
  expanded: boolean;
  onToggle: () => void;
  shelf: "snoozed" | "settled";
  activeThreadId: string | null;
  lifecycle: ReturnType<typeof useLifecycle>;
  onNavigate: () => void;
}) {
  const isCompact = useIsCompactViewport();
  if (threads.length === 0) return null;
  const now = Date.now();
  return (
    <section aria-label={label}>
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={expanded}
        // Padded like a card, so the chevron ends on the same right edge as
        // every row's status and provider glyph. Full width already, so a
        // coarse pointer only needs the height.
        className={cn(
          "mt-3 flex w-full cursor-pointer items-center gap-2 px-2.5 text-left",
          isCompact ? "min-h-11 pb-2" : "pb-1",
        )}
      >
        <span
          className={cn(
            "font-medium text-muted-foreground/70",
            isCompact ? "text-xs" : "text-2xs",
          )}
        >
          {expanded ? label : `${label} (${threads.length})`}
        </span>
        <span className="h-px flex-1 bg-sidebar-border" />
        <span className={TRAILING_GLYPH_BOX_CLASS}>
          <Icon
            name="ChevronDown"
            className={cn(
              "size-3 text-muted-foreground/70 transition-transform",
              expanded && "rotate-180",
            )}
          />
        </span>
      </button>
      {expanded ? (
        <ul className="flex flex-col gap-0.5">
          {threads.map((thread) => (
            <SlimRow
              key={thread.id}
              thread={thread}
              isActive={thread.id === activeThreadId}
              shelf={shelf}
              wakeAt={lifecycle.wakeAtFor(thread)}
              now={now}
              onNavigate={onNavigate}
              onRestore={() =>
                shelf === "snoozed"
                  ? lifecycle.unsnooze(thread.id)
                  : lifecycle.unsettle(thread.id)
              }
            />
          ))}
        </ul>
      ) : null}
    </section>
  );
}

function Shelf({
  label,
  children,
}: {
  label: string | null;
  children: React.ReactNode;
}) {
  return (
    // A named section is exposed as a landmark region; an unnamed one is not,
    // which is exactly right for the single unlabelled inbox list.
    <section {...(label ? { "aria-label": label } : {})}>
      {label ? (
        <h2 className={cn("flex items-center gap-2 px-2.5 pb-1 pt-3")}>
          <span className="text-2xs font-medium text-muted-foreground/70">
            {label}
          </span>
          <span className="h-px flex-1 bg-sidebar-border" />
        </h2>
      ) : null}
      <ul className="flex flex-col gap-0.5">{children}</ul>
    </section>
  );
}
