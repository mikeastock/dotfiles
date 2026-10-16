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
import { buildItems, COARSE_METRICS, FINE_METRICS, foldsFor, wantsRecord } from "./items";
import { COARSE_POINTER_QUERY, COMPACT_VIEWPORT_QUERY, useMediaQuery } from "./useMediaQuery";
import { loadRecord, parseRun, type DiffData, type Loads } from "./model";
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
/** File records read at once; each read is one or more small RPCs. */
const PARALLEL_READS = 3;
const NO_LOADS: Loads = { files: new Map(), failures: new Map() };

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
        setData(parseRun(result));
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
  return { data, error, loading, refresh };
}

/**
 * Reads the records the panel wants, a few at a time, in manifest order:
 * every shown file under the size limit, plus any file the user asked for.
 */
function useRecords(threadId: string, data: DiffData | null, requested: ReadonlySet<string>) {
  const rpc = useRpc<typeof rpcContract>();
  const [loads, setLoads] = useState<Loads>(NO_LOADS);
  const [reading, setReading] = useState<ReadonlySet<number>>(new Set());
  const run = useRef<string | null>(null);
  useEffect(() => {
    run.current = data?.runId ?? null;
    setLoads(NO_LOADS);
    setReading(new Set());
  }, [data]);
  useEffect(() => {
    if (data === null || data.runId !== run.current || reading.size >= PARALLEL_READS) return;
    const next = data.records.findIndex(
      (record, index) =>
        !reading.has(index) &&
        !loads.files.has(index) &&
        !loads.failures.has(index) &&
        wantsRecord(record, filePath(data.inventory[index]!.file), requested),
    );
    if (next < 0) return;
    const { runId } = data;
    setReading((current) => new Set(current).add(next));
    const read = (offset: number, length: number) => rpc.call("read", { threadId, runId, offset, length });
    loadRecord(read, data.records[next]!)
      .then((file) => {
        if (run.current === runId) setLoads((current) => ({ ...current, files: new Map(current.files).set(next, file) }));
      })
      .catch((cause: unknown) => {
        if (run.current === runId) {
          setLoads((current) => ({ ...current, failures: new Map(current.failures).set(next, errorMessage(cause)) }));
        }
      })
      .finally(() => {
        if (run.current !== runId) return;
        setReading((current) => {
          const remaining = new Set(current);
          remaining.delete(next);
          return remaining;
        });
      });
  }, [rpc, threadId, data, loads, reading, requested]);
  /** Forget a failed read so the loader tries it again. */
  const retry = useCallback((index: number) => {
    setLoads((current) => {
      if (!current.failures.has(index)) return current;
      const failures = new Map(current.failures);
      failures.delete(index);
      return { ...current, failures };
    });
  }, []);
  return { loads, reading: reading.size > 0, retry };
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
  const { data, error, loading, refresh } = useDiff(threadId, mode);
  useRefreshAfterTurns(threadId, refresh);

  const codeTheme = useCodeTheme();
  const palette = useMemo(
    () => paletteFromCodeTheme(codeTheme.theme ?? fallbackTheme(codeTheme.mode)),
    [codeTheme.theme, codeTheme.mode],
  );
  const [chosenLayout, setLayout] = useState<Layout>(readLayout);
  // Two code columns do not fit on a phone; the saved choice returns on a wider screen.
  const isCompact = useMediaQuery(COMPACT_VIEWPORT_QUERY);
  const layout: Layout = isCompact ? "unified" : chosenLayout;
  const metrics = useMediaQuery(COARSE_POINTER_QUERY) ? COARSE_METRICS : FINE_METRICS;
  const [folds, setFolds] = useState<ReadonlyMap<number, ReadonlySet<number>>>(new Map());
  const [closed, setClosed] = useState<ReadonlySet<string>>(new Set());
  const [requested, setRequested] = useState<ReadonlySet<string>>(new Set());
  const { loads, reading, retry } = useRecords(threadId, data, requested);
  const [selection, setSelection] = useState<LineSelection | null>(null);
  const [showFiles, setShowFiles] = useState(false);
  const [scrollRequest, setScrollRequest] = useState<{ fileIndex: number; seq: number } | null>(null);

  // Fold ids belong to one diffr run; a new run starts from diffr's defaults.
  // Closed and requested files are kept by path.
  useEffect(() => {
    setFolds(new Map());
    setSelection(null);
  }, [data]);

  const items = useMemo(
    () => (data ? buildItems(data, loads, { layout, palette, folds, closed, requested }) : []),
    [data, loads, layout, palette, folds, closed, requested],
  );

  const toggleFold = useCallback(
    (fileIndex: number, id: number) => {
      const file = loads.files.get(fileIndex);
      if (!file) return;
      setFolds((current) => new Map(current).set(fileIndex, toggled(foldsFor(file, fileIndex, current), id)));
    },
    [loads],
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

  // A second line on the same side of the same file makes a range, so touch
  // screens can select one without shift. Shift-click extends any selection.
  const selectLine = useCallback((fileIndex: number, side: Side, line: number, extend: boolean) => {
    setSelection((current) => {
      const sameSide = current !== null && current.fileIndex === fileIndex && current.side === side;
      if (sameSide && current.start === line && current.end === line) return null;
      if (sameSide && (extend || current.start === current.end)) {
        return { fileIndex, side, start: Math.min(current.start, line), end: Math.max(current.end, line) };
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
      // On a phone this panel covers the composer, so say where the text went.
      if (isCompact) toast.success(`Added ${reference} to your message`);
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
    for (const record of data?.records ?? []) {
      if (record?.summary.kind !== "text") continue;
      added += record.summary.stats.added;
      removed += record.summary.stats.removed;
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
                metrics === COARSE_METRICS && "min-h-8",
                modeKind === option.kind ? "bg-accent text-accent-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {option.label}
            </button>
          ))}
        </div>
        {/* One group, so a narrow panel wraps it to its own row instead of splitting it. */}
        <div className="ml-auto flex items-center gap-1">
          {isCompact ? null : (
            <ToolbarButton label={layout === "unified" ? "Split view" : "Unified view"} onClick={() => changeLayout(layout === "unified" ? "split" : "unified")}>
              <Icon name={layout === "unified" ? "Columns2" : "ListView"} className="size-3.5" />
            </ToolbarButton>
          )}
          <ToolbarButton label="Expand every fold" onClick={expandAll} disabled={!data}>
            <span className="text-[11px]">Expand</span>
          </ToolbarButton>
          <ToolbarButton label="Restore diffr's folds" onClick={resetFolds} disabled={!data}>
            <span className="text-[11px]">Fold</span>
          </ToolbarButton>
          <ToolbarButton label="Run diffr again" onClick={refresh} disabled={loading}>
            <Icon name={loading || reading ? "Spinner" : "RotateCcw"} className={cn("size-3.5", (loading || reading) && "animate-spin")} />
          </ToolbarButton>
        </div>
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
          <button type="submit" className="rounded border border-border px-2 py-0.5 text-xs hover:bg-accent [@media(pointer:coarse)]:min-h-8">
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
            className="flex shrink-0 items-center gap-1 whitespace-nowrap hover:text-foreground [@media(pointer:coarse)]:min-h-8"
            title={`diffr ${data.args.join(" ")}`}
          >
            <span aria-hidden>{showFiles ? "▾" : "▸"}</span>
            {data.inventory.length} {data.inventory.length === 1 ? "file" : "files"}
          </button>
          <span className="shrink-0 whitespace-nowrap font-mono tabular-nums">
            <span className="text-green-600 dark:text-green-400">+{totals.added}</span>{" "}
            <span className="text-red-600 dark:text-red-400">−{totals.removed}</span>
          </span>
          <span className="min-w-0 flex-1 truncate">{comparisonLabel(data.comparison.lhs, data.comparison.rhs)}</span>
        </div>
      ) : null}
      {reference ? (
        <div className="flex items-center gap-2 border-b border-border px-2 py-1 text-xs">
          <span className="min-w-0 flex-1 truncate font-mono" title={reference}>
            {reference}
          </span>
          <button
            type="button"
            onClick={addToChat}
            aria-label={`Add ${reference} to chat`}
            className="shrink-0 rounded bg-accent px-2 py-0.5 text-accent-foreground [@media(pointer:coarse)]:min-h-8"
          >
            Add to chat
          </button>
          <ToolbarButton label="Clear selection" onClick={() => setSelection(null)}>
            <span aria-hidden>×</span>
          </ToolbarButton>
        </div>
      ) : null}
      {data && showFiles ? (
        <ul className="max-h-[40%] shrink-0 overflow-y-auto border-b border-border py-1 text-xs">
          {data.inventory.map((entry, fileIndex) => {
            const summary = data.records[fileIndex]?.summary;
            const stats = summary?.kind === "text" ? summary.stats : null;
            return (
              <li key={fileIndex}>
                <button
                  type="button"
                  className="flex w-full items-center gap-2 px-2 py-0.5 text-left hover:bg-accent [@media(pointer:coarse)]:py-2"
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
          loads={loads}
          items={items}
          palette={palette}
          layout={layout}
          metrics={metrics}
          closed={closed}
          selection={selection}
          scrollRequest={scrollRequest}
          onToggleFold={toggleFold}
          onToggleFile={(path) => setClosed((current) => toggled(current, path))}
          onLoadFile={(path) => {
            setRequested((current) => new Set(current).add(path));
            const index = data.inventory.findIndex((entry) => filePath(entry.file) === path);
            if (index >= 0) retry(index);
          }}
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
      className="flex h-6 min-w-6 items-center justify-center rounded px-1 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-50 [@media(pointer:coarse)]:h-8 [@media(pointer:coarse)]:min-w-8"
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
