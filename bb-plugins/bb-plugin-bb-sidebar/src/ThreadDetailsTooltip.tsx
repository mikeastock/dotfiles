import { useEffect, useId, useState, type ReactElement } from "react";
import {
  experimental_useProviders as useProviders,
  experimental_useSidebarThreads as useSidebarThreads,
  experimental_useSidebarThreadActions as useSidebarThreadActions,
  useRpc,
  useRealtime,
  type PluginSidebarThread,
} from "@get-bb/plugin-sdk/app";
import type { bbSidebarRpcContract } from "./server";
import { ThreadHoverCard } from "./components/ThreadHoverCard";
import { threadDisplayTitle } from "./inbox";
import { Icon, type IconName } from "./components/Icon";
import { ProviderGlyph } from "./ProviderGlyph";
import { StatusGlyph } from "./StatusGlyph";
import { ProjectFavicon } from "./ProjectFavicon";
import { PROJECT_ICONS_CHANNEL, projectIconUrl } from "./project-icons";
import { OpenPortDetails } from "./OpenPorts";

export function ThreadDetailsTooltip({
  thread,
  disabled,
  children,
}: {
  thread: PluginSidebarThread;
  disabled: boolean;
  children: ReactElement;
}) {
  const { providers } = useProviders();
  const { projects, threads } = useSidebarThreads();
  const actions = useSidebarThreadActions();
  const { call } = useRpc<typeof bbSidebarRpcContract>();
  const [iconRevision, setIconRevision] = useState(0);
  useRealtime(PROJECT_ICONS_CHANNEL, () => {
    setIconRevision((revision) => revision + 1);
  });
  const [open, setOpen] = useState(false);
  const [subthreadsExpanded, setSubthreadsExpanded] = useState(false);
  const subthreadsId = useId();
  const [execution, setExecution] = useState({ model: "Loading…", reasoningLevel: "" });
  const visible = open && !disabled;

  useEffect(() => {
    setSubthreadsExpanded(false);
    if (!visible) return;
    let cancelled = false;
    setExecution({ model: "Loading…", reasoningLevel: "" });
    void call("getThreadExecutionDetails", { threadId: thread.id }).then(
      (details) => {
        if (!cancelled) {
          setExecution(details ?? { model: "Not set", reasoningLevel: "" });
        }
      },
      () => {
        if (!cancelled) setExecution({ model: "Unavailable", reasoningLevel: "" });
      },
    );
    return () => { cancelled = true; };
  }, [call, thread.id, visible]);

  const provider = providers.find((entry) => entry.id === thread.providerId);
  const project = projects.find((entry) => entry.id === thread.projectId);
  const isWorktree =
    thread.environment?.workspaceDisplayKind === "managed-worktree" ||
    thread.environment?.workspaceDisplayKind === "unmanaged-worktree";
  const status = thread.hasPendingInteraction ? "Needs you" : thread.indicatorLabel ?? "Idle";
  const subthreads = visible ? threads
    .filter((child) => !child.isArchived && child.parentThreadId === thread.id && child.id !== thread.id)
    .sort((left, right) => left.createdAt - right.createdAt || left.id.localeCompare(right.id)) : [];
  const label = (
    <div className="flex flex-col gap-2">
      <div className="truncate text-xs font-semibold leading-4 text-popover-foreground">
        {threadDisplayTitle(thread)}
      </div>
      <div className="flex flex-col gap-1.5 text-xs leading-4 text-muted-foreground">
        {project ? (
          <div className="flex items-center gap-2">
            <ProjectFavicon
              src={projectIconUrl(project.id, iconRevision)}
              fallback={<Icon name="FolderGit" className="size-3.5 shrink-0" aria-hidden />}
            />
            <span className="truncate"><span className="sr-only">Project: </span>{project.name}</span>
          </div>
        ) : null}
        {thread.host ? <DetailRow icon="Computer" label="Machine" value={thread.host.name} /> : null}
        {thread.environment?.branchName ? (
          <DetailRow
            icon={isWorktree ? "FolderGit" : "GitBranch"}
            label={isWorktree ? "Worktree branch" : "Branch"}
            value={thread.environment.branchName}
          />
        ) : null}
        <div className="flex items-start gap-2">
          <span className="relative mt-px flex size-3.5 shrink-0 items-center justify-center">
            <ProviderGlyph providerId={thread.providerId} provider={provider ?? null} className="size-3.5 [&_span]:size-3.5" />
            {thread.indicator !== "none" ? (
              <span className="absolute -bottom-1 -right-1 rounded-full bg-popover">
                <StatusGlyph indicator={thread.indicator} label={status} className="size-2.5" />
              </span>
            ) : null}
          </span>
          <div className="min-w-0 flex-1">
            <div className="break-words"><span className="sr-only">Model: </span>{execution.model}</div>
            <div className="text-[11px] leading-4">
              <span className="sr-only">Provider: </span>{provider?.displayName ?? thread.providerId}
              {execution.reasoningLevel ? <><span aria-hidden> · </span><span className="sr-only">Reasoning: </span>{execution.reasoningLevel}</> : null}
            </div>
          </div>
        </div>
        <span className="sr-only">Status: {status}</span>
        {subthreads.length > 0 ? (
          <div className="flex min-w-0 flex-col gap-1.5">
            <button
              type="button"
              aria-expanded={subthreadsExpanded}
              aria-controls={subthreadsExpanded ? subthreadsId : undefined}
              onClick={(event) => {
                event.stopPropagation();
                setSubthreadsExpanded((expanded) => !expanded);
              }}
              className="pointer-events-auto flex items-center gap-2 rounded-sm text-left hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <Icon name="Workflow" className="size-3.5 shrink-0" aria-hidden />
              <span>Subthreads ({subthreads.length})</span>
              <Icon name={subthreadsExpanded ? "ChevronUp" : "ChevronDown"} className="ml-auto size-3 shrink-0" aria-hidden />
            </button>
            {subthreadsExpanded ? <ul id={subthreadsId} aria-label="Subthreads" className="pointer-events-auto flex max-h-[min(12rem,30dvh)] flex-col gap-1.5 overflow-y-auto">
              {subthreads.map((child) => {
                const childProvider = providers.find((entry) => entry.id === child.providerId);
                const childStatus = child.hasPendingInteraction ? "Needs you" : child.indicatorLabel ?? "Idle";
                return (
                  <li key={child.id} className="min-w-0 pl-5">
                    <button
                      type="button"
                      aria-label={`Open subthread: ${threadDisplayTitle(child)}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        setOpen(false);
                        actions.open(child.id);
                      }}
                      className="flex w-full min-w-0 items-start gap-2 rounded-sm text-left hover:text-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                    >
                      <ProviderGlyph providerId={child.providerId} provider={childProvider ?? null} className="mt-px size-3.5 shrink-0 [&_span]:size-3.5" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate">{threadDisplayTitle(child)}</span>
                        <span className="flex items-center gap-1 text-[11px] leading-4 text-muted-foreground">
                          <span className="truncate">{childProvider?.displayName ?? child.providerId} · {childStatus}</span>
                          <StatusGlyph indicator={child.hasPendingInteraction ? "waiting-for-input" : child.indicator} label={null} className="size-2.5" />
                        </span>
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul> : null}
          </div>
        ) : null}
        <OpenPortDetails thread={thread} />
      </div>
    </div>
  );

  return (
    <ThreadHoverCard
      content={label}
      open={visible}
      onOpenChange={setOpen}
    >
      {children}
    </ThreadHoverCard>
  );
}

function DetailRow({ icon, label, value }: { icon: IconName; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <Icon name={icon} className="size-3.5 shrink-0" aria-hidden />
      <span className="truncate" title={value}><span className="sr-only">{label}: </span>{value}</span>
    </div>
  );
}
