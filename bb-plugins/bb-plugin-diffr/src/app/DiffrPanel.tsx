// The Diffr thread panel: runs diffr on the thread's workspace and draws the
// result with diffr's own fold model.
import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  experimental_copyToClipboard as copyToClipboard,
  experimental_useCodeTheme as useCodeTheme,
  experimental_useSidebarThreads as useSidebarThreads,
  useComposers,
  useRpc,
  type PluginCodeThemeData,
  type PluginThreadPanelProps,
} from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { rpcContract } from "../../server";
import type { DiffMode } from "../contract";
import { comparisonLabel, snapshotLabel } from "../vendor/diffr/document/counts";
import type { Layout } from "../vendor/diffr/document/rows";
import { filePath } from "../vendor/diffr/protocol/wire";
import { Icon } from "@/components/ui/icon";
import { cn } from "@/lib/utils";
import { DiffList, type LineSelection, type Side } from "./DiffList";
import { buildItems, foldsFor } from "./items";
import { parseDiff, type DiffData } from "./model";
import { paletteFromCodeTheme } from "./palette";
import { splitArgs } from "./args";

type ModeKind = DiffMode["kind"];

const MODES: { kind: ModeKind; label: string; title: string }[] = [
  { kind: "changes", label: "Changes", title: "HEAD against the working tree, including untracked files" },
  { kind: "branch", label: "Branch", title: "The merge base with the base branch against the working tree" },
  { kind: "custom", label: "Custom", title: "diffr arguments, as git diff takes them" },
];

const LAYOUT_KEY = "bb-diffr:layout";
const BUSY = new Set(["starting", "active", "stopping"]);

function fallbackTheme(mode: "dark" | "light"): PluginCodeThemeData {
  return mode === "light"
    ? { name: "fallback-light", type: "light", fg: "#1f2328", bg: "#ffffff", colors: {}, tokenColors: [] }
    : { name: "fallback-dark", type: "dark", fg: "#d4d4d4", bg: "#1e1e1e", colors: {}, tokenColors: [] };
}

function readLayout(): Layout {
  try {
    return localStorage.getItem(LAYOUT_KEY) === "split" ? "split" : "unified";
  } catch {
    return "unified";
  }
}

function errorMessage(cause: unknown) {
  return cause instanceof Error ? cause.message : String(cause);
}

/** Runs diffr through the server and keeps the latest result. */
function useDiff(threadId: string, mode: DiffMode) {
  const rpc = useRpc<typeof rpcContract>();
  const [data, setData] = useState<DiffData | null>(null);
  const [args, setArgs] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const request = useRef(0);
  const modeKey = JSON.stringify(mode);
  const refresh = useCallback(() => {
    const id = ++request.current;
    setLoading(true);
    rpc
      .call("diff", { threadId, mode: JSON.parse(modeKey) as DiffMode })
      .then((result) => {
        if (id !== request.current) return;
        setData(parseDiff(result.ndjson));
        setArgs(result.args);
        setError(null);
      })
      .catch((cause: unknown) => {
        if (id === request.current) setError(errorMessage(cause));
      })
      .finally(() => {
        if (id === request.current) setLoading(false);
      });
  }, [rpc, threadId, modeKey]);
  useEffect(refresh, [refresh]);
  return { data, args, error, loading, refresh };
}

/** Run again when the thread's agent finishes a turn, since it may have edited files. */
function useRefreshAfterTurns(threadId: string, refresh: () => void) {
  const { threads } = useSidebarThreads();
  const status = threads.find((thread) => thread.id === threadId)?.status;
  const previous = useRef(status);
  useEffect(() => {
    const wasBusy = previous.current !== undefined && BUSY.has(previous.current);
    previous.current = status;
    if (wasBusy && status !== undefined && !BUSY.has(status)) refresh();
  }, [status, refresh]);
}

function toggled<T>(set: ReadonlySet<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

export function DiffrPanel({ threadId }: PluginThreadPanelProps) {
  const [modeKind, setModeKind] = useState<ModeKind>("changes");
  const [customText, setCustomText] = useState("");
  const [customArgs, setCustomArgs] = useState<string[]>([]);
  const mode = useMemo<DiffMode>(
    () => (modeKind === "custom" ? { kind: "custom", args: customArgs } : { kind: modeKind }),
    [modeKind, customArgs],
  );
  const { data, args, error, loading, refresh } = useDiff(threadId, mode);
  useRefreshAfterTurns(threadId, refresh);

  const codeTheme = useCodeTheme();
  const palette = useMemo(
    () => paletteFromCodeTheme(codeTheme.theme ?? fallbackTheme(codeTheme.mode)),
    [codeTheme.theme, codeTheme.mode],
  );
  const [layout, setLayout] = useState<Layout>(readLayout);
  const [folds, setFolds] = useState<ReadonlyMap<number, ReadonlySet<number>>>(new Map());
  const [closed, setClosed] = useState<ReadonlySet<string>>(new Set());
  const [loaded, setLoaded] = useState<ReadonlySet<string>>(new Set());
  const [selection, setSelection] = useState<LineSelection | null>(null);
  const [showFiles, setShowFiles] = useState(false);
  const [scrollRequest, setScrollRequest] = useState<{ fileIndex: number; seq: number } | null>(null);

  // Fold ids belong to one diffr run; a new run starts from diffr's defaults.
  // Closed and loaded files are kept by path.
  useEffect(() => {
    setFolds(new Map());
    setSelection(null);
  }, [data]);

  const items = useMemo(
    () => (data ? buildItems(data, { layout, palette, folds, closed, loaded }) : []),
    [data, layout, palette, folds, closed, loaded],
  );

  const toggleFold = useCallback(
    (fileIndex: number, id: number) => {
      const file = data?.files[fileIndex];
      if (!file) return;
      setFolds((current) => new Map(current).set(fileIndex, toggled(foldsFor(file, fileIndex, current), id)));
    },
    [data],
  );
  const expandAll = () => {
    if (!data) return;
    setFolds(new Map(data.inventory.map((_, index) => [index, new Set<number>()])));
    setClosed(new Set());
  };
  const resetFolds = () => {
    setFolds(new Map());
    setClosed(new Set());
  };
  const changeLayout = (next: Layout) => {
    setLayout(next);
    try {
      localStorage.setItem(LAYOUT_KEY, next);
    } catch {
      // Storage can be unavailable; the choice then lasts for this panel only.
    }
  };

  const selectLine = useCallback((fileIndex: number, side: Side, line: number, extend: boolean) => {
    setSelection((current) => {
      if (extend && current && current.fileIndex === fileIndex && current.side === side) {
        return { fileIndex, side, start: Math.min(current.start, line), end: Math.max(current.end, line) };
      }
      if (current && current.fileIndex === fileIndex && current.side === side && current.start === line && current.end === line) {
        return null;
      }
      return { fileIndex, side, start: line, end: line };
    });
  }, []);

  const composers = useComposers();
  const reference = selection && data ? selectionReference(data, selection) : null;
  const addToChat = async () => {
    if (!reference) return;
    const composer = composers.find((candidate) => candidate.scope.kind === "thread" && candidate.scope.threadId === threadId);
    if (composer) {
      composer.insert(`${reference} `, { at: "end" });
      composer.focus();
      setSelection(null);
      return;
    }
    if (await copyToClipboard({ text: reference })) toast.success(`Copied ${reference}`);
    else toast.error("Could not reach this thread's composer or the clipboard");
  };

  const runCustom = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      setCustomArgs(splitArgs(customText));
    } catch (cause) {
      toast.error(errorMessage(cause));
    }
  };

  const totals = useMemo(() => {
    let added = 0;
    let removed = 0;
    for (const file of data?.files ?? []) {
      if (file?.diff.type !== "text") continue;
      added += file.diff.stats.textual.added;
      removed += file.diff.stats.textual.removed;
    }
    return { added, removed };
  }, [data]);

  return (
    <div className="flex h-full min-h-0 flex-col bg-background text-foreground">
      <div className="flex flex-wrap items-center gap-2 border-b border-border px-2 py-1.5">
        <div role="radiogroup" aria-label="Comparison" className="flex rounded-md border border-border p-0.5">
          {MODES.map((option) => (
            <button
              key={option.kind}
              type="button"
              role="radio"
              aria-checked={modeKind === option.kind}
              title={option.title}
              onClick={() => setModeKind(option.kind)}
              className={cn(
                "rounded px-2 py-0.5 text-xs",
                modeKind === option.kind ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
        <div className="flex-1" />
        <ToolbarButton label={layout === "unified" ? "Split view" : "Unified view"} onClick={() => changeLayout(layout === "unified" ? "split" : "unified")}>
          <Icon name={layout === "unified" ? "Columns2" : "ListView"} className="size-3.5" />
        </ToolbarButton>
        <ToolbarButton label="Expand every fold" onClick={expandAll} disabled={!data}>
          <span className="text-[11px]">Expand</span>
        </ToolbarButton>
        <ToolbarButton label="Restore diffr's folds" onClick={resetFolds} disabled={!data}>
          <span className="text-[11px]">Fold</span>
        </ToolbarButton>
        <ToolbarButton label="Run diffr again" onClick={refresh} disabled={loading}>
          <Icon name={loading ? "Spinner" : "RotateCcw"} className={cn("size-3.5", loading && "animate-spin")} />
        </ToolbarButton>
      </div>
      {modeKind === "custom" ? (
        <form onSubmit={runCustom} className="flex items-center gap-2 border-b border-border px-2 py-1.5">
          <span className="font-mono text-xs text-muted-foreground">diffr</span>
          <input
            value={customText}
            onChange={(event) => setCustomText(event.target.value)}
            placeholder="main...HEAD -- src/"
            aria-label="diffr arguments"
            className="min-w-0 flex-1 rounded border border-border bg-transparent px-2 py-0.5 font-mono text-xs outline-none focus:border-ring"
          />
          <button type="submit" className="rounded border border-border px-2 py-0.5 text-xs hover:bg-accent">
            Run
          </button>
        </form>
      ) : null}
      {data ? (
        <div className="flex items-center gap-2 border-b border-border px-2 py-1 text-xs text-muted-foreground">
          <button
            type="button"
            aria-expanded={showFiles}
            onClick={() => setShowFiles((value) => !value)}
            className="flex items-center gap-1 hover:text-foreground"
            title={`diffr ${args.join(" ")}`}
          >
            <span aria-hidden>{showFiles ? "▾" : "▸"}</span>
            {data.inventory.length} {data.inventory.length === 1 ? "file" : "files"}
          </button>
          <span className="font-mono tabular-nums">
            <span className="text-green-600 dark:text-green-400">+{totals.added}</span>{" "}
            <span className="text-red-600 dark:text-red-400">−{totals.removed}</span>
          </span>
          <span className="min-w-0 flex-1 truncate">{comparisonLabel(data.comparison.lhs, data.comparison.rhs)}</span>
          {reference ? (
            <button
              type="button"
              onClick={addToChat}
              className="shrink-0 truncate rounded bg-accent px-2 py-0.5 text-accent-foreground"
              title="Add the selected lines to this thread's message"
            >
              Add {reference} to chat
            </button>
          ) : null}
        </div>
      ) : null}
      {data && showFiles ? (
        <ul className="max-h-[40%] shrink-0 overflow-y-auto border-b border-border py-1 text-xs">
          {data.inventory.map((entry, fileIndex) => {
            const file = data.files[fileIndex];
            const stats = file?.diff.type === "text" ? file.diff.stats.textual : null;
            return (
              <li key={fileIndex}>
                <button
                  type="button"
                  className="flex w-full items-center gap-2 px-2 py-0.5 text-left hover:bg-accent"
                  onClick={() => setScrollRequest({ fileIndex, seq: Date.now() })}
                >
                  <span className="min-w-0 flex-1 truncate font-mono">{filePath(entry.file)}</span>
                  {stats ? (
                    <span className="font-mono tabular-nums text-muted-foreground">
                      +{stats.added} −{stats.removed}
                    </span>
                  ) : null}
                </button>
              </li>
            );
          })}
        </ul>
      ) : null}
      {error ? (
        <p role="alert" className="whitespace-pre-wrap border-b border-border px-3 py-2 text-xs text-destructive">
          {error}
        </p>
      ) : null}
      {data?.errors.map((problem) => (
        <p key={problem} role="alert" className="border-b border-border px-3 py-1 text-xs text-destructive">
          {problem}
        </p>
      ))}
      {data === null ? (
        <EmptyState>{error ? "diffr did not run." : "Running diffr…"}</EmptyState>
      ) : data.inventory.length === 0 ? (
        <EmptyState>No changes.</EmptyState>
      ) : (
        <DiffList
          data={data}
          items={items}
          palette={palette}
          layout={layout}
          closed={closed}
          selection={selection}
          scrollRequest={scrollRequest}
          onToggleFold={toggleFold}
          onToggleFile={(path) => setClosed((current) => toggled(current, path))}
          onLoadFile={(path) => setLoaded((current) => new Set(current).add(path))}
          onSelectLine={selectLine}
        />
      )}
    </div>
  );
}

/** `path:12` or `path:12-20`; lines from the old side say so. */
function selectionReference(data: DiffData, selection: LineSelection): string {
  const entry = data.inventory[selection.fileIndex]!;
  const ref = selection.side === "old" ? (entry.file.lhs ?? entry.file.rhs)! : (entry.file.rhs ?? entry.file.lhs)!;
  const lines = selection.start === selection.end ? `${selection.start}` : `${selection.start}-${selection.end}`;
  return `${ref.path}:${lines}${selection.side === "old" ? ` (at ${snapshotLabel(data.comparison.lhs)})` : ""}`;
}

function ToolbarButton({
  label,
  onClick,
  disabled,
  children,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      disabled={disabled}
      className="flex h-6 min-w-6 items-center justify-center rounded px-1 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50"
    >
      {children}
    </button>
  );
}

function EmptyState({ children }: { children: ReactNode }) {
  return (
    <div role="status" className="m-3 rounded-lg border border-dashed border-border px-4 py-6 text-center text-sm text-muted-foreground">
      {children}
    </div>
  );
}
