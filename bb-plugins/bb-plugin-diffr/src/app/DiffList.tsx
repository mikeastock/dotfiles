// The virtual list that draws diffr's rows. Rows have fixed heights, so only
// the ones in view are mounted, however large the diff.
import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from "react";
import { foldBackground, type Layout, type RenderSpan, type SplitLineCell, type UnifiedLineCell } from "../vendor/diffr/document/rows";
import type { Palette } from "../vendor/diffr/theme/palette";
import { filePath, type FileChange } from "../vendor/diffr/protocol/wire";
import { itemHeight, type Item, type Metrics } from "./items";
import type { DiffData } from "./model";

export type Side = "old" | "new";

export interface LineSelection {
  fileIndex: number;
  side: Side;
  start: number;
  end: number;
}

export interface DiffListProps {
  data: DiffData;
  items: Item[];
  palette: Palette;
  layout: Layout;
  metrics: Metrics;
  closed: ReadonlySet<string>;
  selection: LineSelection | null;
  scrollRequest: { fileIndex: number; seq: number } | null;
  onToggleFold(fileIndex: number, id: number): void;
  onToggleFile(path: string): void;
  onLoadFile(path: string): void;
  onSelectLine(fileIndex: number, side: Side, line: number, extend: boolean): void;
}

const OVERSCAN = 12;

const STATUS: Record<FileChange["status"], { letter: string; title: string }> = {
  added: { letter: "A", title: "Added" },
  deleted: { letter: "D", title: "Deleted" },
  modified: { letter: "M", title: "Modified" },
  renamed: { letter: "R", title: "Renamed" },
  copied: { letter: "C", title: "Copied" },
  type_changed: { letter: "T", title: "Type changed" },
};

const textWidth = (spans: RenderSpan[]) => spans.reduce((sum, span) => sum + span.text.length, 0);

/** The widest content in characters, so unified rows can scroll sideways together. */
function contentColumns(items: Item[]): number {
  let widest = 0;
  for (const item of items) {
    if (item.kind !== "row") continue;
    const cell = item.row.cell;
    if (cell) widest = Math.max(widest, textWidth(cell.spans));
  }
  return widest;
}

/** Digits for the widest line number in any file. */
function lineDigits(data: DiffData): number {
  let lines = 0;
  for (const file of data.files) {
    if (file?.diff.type !== "text") continue;
    for (const side of [file.diff.lhs, file.diff.rhs]) {
      if (side) lines = Math.max(lines, side.text.split("\n").length);
    }
  }
  return Math.max(3, String(lines).length);
}

function useViewport(ref: RefObject<HTMLDivElement | null>) {
  const [size, setSize] = useState({ width: 0, height: 0 });
  useLayoutEffect(() => {
    const element = ref.current;
    if (!element) return;
    const update = () => setSize({ width: element.clientWidth, height: element.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(element);
    return () => observer.disconnect();
  }, [ref]);
  return size;
}

export function DiffList(props: DiffListProps) {
  const { data, items, palette, layout, metrics, scrollRequest } = props;
  const scroller = useRef<HTMLDivElement>(null);
  const viewport = useViewport(scroller);
  const [scrollTop, setScrollTop] = useState(0);

  const offsets = useMemo(() => {
    const result = new Array<number>(items.length + 1);
    result[0] = 0;
    items.forEach((item, index) => {
      result[index + 1] = result[index]! + itemHeight(item, metrics);
    });
    return result;
  }, [items, metrics]);
  const total = offsets[items.length]!;
  const digits = useMemo(() => lineDigits(data), [data]);
  const columns = useMemo(() => (layout === "unified" ? contentColumns(items) : 0), [items, layout]);

  useEffect(() => {
    if (scrollRequest === null || !scroller.current) return;
    const index = items.findIndex((item) => item.kind === "header" && item.fileIndex === scrollRequest.fileIndex);
    if (index >= 0) scroller.current.scrollTop = offsets[index]!;
    // Only a new request scrolls; later item changes must not snap back.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scrollRequest]);

  // First item whose bottom is below the top of the view.
  let low = 0;
  let high = items.length;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (offsets[mid + 1]! <= scrollTop) low = mid + 1;
    else high = mid;
  }
  const first = Math.max(0, low - OVERSCAN);
  let last = low;
  while (last < items.length && offsets[last]! < scrollTop + viewport.height) last++;
  last = Math.min(items.length, last + OVERSCAN);

  // Gutter: chevron, line number(s), sign.
  const numberColumns = layout === "unified" ? 2 * (digits + 2) : digits + 2;
  const innerWidth =
    layout === "unified"
      ? `max(100%, calc(${metrics.chevron}px + ${numberColumns + 2 + columns + 2}ch))`
      : "100%";

  const mounted: ReactNode[] = [];
  for (let index = first; index < last; index++) {
    const item = items[index]!;
    mounted.push(
      <div
        key={item.key}
        style={{ position: "absolute", top: offsets[index], left: 0, width: "100%", height: itemHeight(item, metrics) }}
      >
        <ItemView {...props} item={item} digits={digits} viewportWidth={viewport.width} />
      </div>,
    );
  }

  return (
    <div
      ref={scroller}
      className="min-h-0 flex-1 overflow-auto font-mono text-xs"
      style={{ background: palette.bg, color: palette.fg, lineHeight: `${metrics.row}px` }}
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
    >
      <div style={{ position: "relative", height: total, width: innerWidth }}>{mounted}</div>
    </div>
  );
}

type ItemViewProps = DiffListProps & { item: Item; digits: number; viewportWidth: number };

function ItemView(props: ItemViewProps) {
  const { item } = props;
  if (item.kind === "header") return <FileHeader {...props} fileIndex={item.fileIndex} />;
  if (item.kind === "note") return <Note {...props} item={item} />;
  const { row } = item;
  if (row.cell) return <UnifiedRow {...props} fileIndex={item.fileIndex} cell={row.cell} />;
  return (
    <div className="flex h-full" style={{ width: props.viewportWidth || "100%" }}>
      <SplitHalf {...props} fileIndex={item.fileIndex} cell={row.left!} side="old" />
      <div style={{ width: 1, background: props.palette.guide }} />
      <SplitHalf {...props} fileIndex={item.fileIndex} cell={row.right!} side="new" />
    </div>
  );
}

function FileHeader(props: ItemViewProps & { fileIndex: number }) {
  const { data, palette, fileIndex, closed, onToggleFile, viewportWidth } = props;
  const entry = data.inventory[fileIndex]!;
  const path = filePath(entry.file);
  const isClosed = closed.has(path);
  const file = data.files[fileIndex];
  const status = STATUS[entry.status];
  const slash = path.lastIndexOf("/");
  const renamedFrom = entry.file.lhs && entry.file.rhs && entry.file.lhs.path !== entry.file.rhs.path ? entry.file.lhs.path : null;
  const stats = file?.diff.type === "text" ? file.diff.stats : null;
  const statusColor =
    entry.status === "added" ? palette.addedText : entry.status === "deleted" ? palette.removedText : palette.accent;
  return (
    <button
      type="button"
      onClick={() => onToggleFile(path)}
      aria-expanded={!isClosed}
      title={path}
      className="flex h-full items-center gap-2 border-y px-2 text-left font-sans text-xs"
      style={{
        position: "sticky",
        left: 0,
        width: viewportWidth || "100%",
        background: palette.fileHeader,
        borderColor: palette.guide,
        color: palette.fg,
      }}
    >
      <span aria-hidden style={{ width: 10, color: palette.muted }}>
        {isClosed ? "▸" : "▾"}
      </span>
      <span title={status.title} className="font-mono font-semibold" style={{ color: statusColor }}>
        {status.letter}
      </span>
      {/* The directory gives way first, so a narrow panel still shows the file name. */}
      <span className="flex min-w-0 flex-1">
        <span className="min-w-0 truncate" style={{ color: palette.fileHeaderDir }}>
          {renamedFrom ? `${renamedFrom} → ` : null}
          {path.slice(0, slash + 1)}
        </span>
        <span className="min-w-0 shrink-0 truncate font-medium" style={{ maxWidth: "100%" }}>
          {path.slice(slash + 1)}
        </span>
      </span>
      {entry.tags.map((tag) => (
        <span key={tag} className="hidden rounded px-1 text-[10px] sm:inline" style={{ background: palette.chrome, color: palette.muted }}>
          {tag}
        </span>
      ))}
      {stats?.fallback ? (
        <span title={`Line diff: ${stats.fallback.message}`} className="hidden sm:inline" style={{ color: palette.muted }}>
          line diff
        </span>
      ) : null}
      {file?.diff.type === "binary" ? <span style={{ color: palette.muted }}>binary</span> : null}
      {stats ? (
        <span className="font-mono tabular-nums">
          <span style={{ color: palette.addedText }}>+{stats.textual.added}</span>{" "}
          <span style={{ color: palette.removedText }}>−{stats.textual.removed}</span>
        </span>
      ) : null}
    </button>
  );
}

function Note(props: ItemViewProps & { item: Extract<Item, { kind: "note" }> }) {
  const { item, palette, data, onLoadFile, viewportWidth } = props;
  const style = {
    position: "sticky" as const,
    left: 0,
    width: viewportWidth || "100%",
    paddingLeft: props.metrics.chevron + 8,
    color: item.tone === "error" ? palette.removedText : item.tone === "load" ? palette.accent : palette.muted,
  };
  if (item.tone === "load") {
    const path = filePath(data.inventory[item.fileIndex]!.file);
    return (
      <button type="button" className="block h-full truncate text-left hover:underline" style={style} onClick={() => onLoadFile(path)}>
        {item.text}
      </button>
    );
  }
  return (
    <div className="h-full truncate" style={style}>
      {item.text}
    </div>
  );
}

function rowBackground(palette: Palette, cell: SplitLineCell | UnifiedLineCell): string {
  if (cell.band) return foldBackground(palette, cell.band);
  if (cell.kind === "addition") return palette.addition;
  if (cell.kind === "deletion") return palette.deletion;
  if (cell.kind === "empty") return palette.chrome;
  return palette.bg;
}

/**
 * diffr marks every byte of a wholly new or removed line as changed. The row
 * tint already says so; word emphasis is only useful inside an edited line.
 */
function emphasis(spans: RenderSpan[], palette: Palette): RenderSpan[] {
  const isWord = (span: RenderSpan) => span.bg === palette.addWord || span.bg === palette.deleteWord;
  // An inline fold label and the closer after it are not source on this line.
  const label = spans.findIndex((span) => span.fg === palette.foldPlaceholder && span.text.includes("⋯"));
  const source = label < 0 ? spans : spans.slice(0, label);
  const whole =
    source.some(isWord) && source.every((span) => isWord(span) || span.guide !== undefined || span.text.trim() === "");
  return whole ? spans.map((span) => (isWord(span) ? { ...span, bg: undefined } : span)) : spans;
}

function Spans({ spans }: { spans: RenderSpan[] }) {
  return (
    <>
      {spans.map((span, index) => (
        <span key={index} style={{ color: span.fg, backgroundColor: span.bg }}>
          {span.text}
        </span>
      ))}
    </>
  );
}

function Chevron(props: ItemViewProps & { fileIndex: number; cell: SplitLineCell | UnifiedLineCell }) {
  const { cell, palette, fileIndex, onToggleFold, metrics } = props;
  const fold = cell.fold;
  return (
    <span className="inline-flex shrink-0 justify-center" style={{ width: metrics.chevron }}>
      {fold ? (
        <button
          type="button"
          aria-label={fold.collapsed ? "Expand" : "Collapse"}
          aria-expanded={!fold.collapsed}
          className="w-full hover:opacity-100"
          style={{ color: palette.foldPlaceholder, opacity: fold.collapsed ? 1 : 0.6 }}
          onClick={() => onToggleFold(fileIndex, fold.id)}
        >
          {fold.collapsed ? "▸" : "▾"}
        </button>
      ) : null}
    </span>
  );
}

function LineNumber(props: ItemViewProps & { fileIndex: number; side: Side; line: number | undefined }) {
  const { line, side, fileIndex, digits, palette, selection, onSelectLine } = props;
  const selected =
    line !== undefined &&
    selection !== null &&
    selection.fileIndex === fileIndex &&
    selection.side === side &&
    line >= selection.start &&
    line <= selection.end;
  const style = {
    width: `${digits + 2}ch`,
    color: selected ? palette.fg : palette.muted,
    background: selected ? palette.selection : undefined,
  };
  if (line === undefined) return <span className="shrink-0" style={style} />;
  return (
    <button
      type="button"
      title="Select line; select another line to make a range"
      aria-label={`Select ${side} line ${line}`}
      className="shrink-0 pr-[1ch] text-right tabular-nums hover:underline"
      style={style}
      onClick={(event) => onSelectLine(fileIndex, side, line, event.shiftKey)}
    >
      {line}
    </button>
  );
}

/** A collapsed band or label row toggles its fold when clicked anywhere. */
function bandToggle(cell: SplitLineCell | UnifiedLineCell): number | undefined {
  if (!cell.band) return undefined;
  return cell.fold?.id ?? cell.labelOf;
}

function Content(props: ItemViewProps & { fileIndex: number; cell: SplitLineCell | UnifiedLineCell; clip: boolean }) {
  const { cell, palette, fileIndex, onToggleFold, clip } = props;
  const toggle = bandToggle(cell);
  const signColor =
    cell.kind === "addition" ? palette.addedText : cell.kind === "deletion" ? palette.removedText : palette.muted;
  const body = (
    <>
      <span className="inline-block shrink-0" style={{ width: "2ch", color: signColor }}>
        {cell.band ? " " : cell.sign}
      </span>
      <span className={clip ? "min-w-0 overflow-hidden whitespace-pre" : "whitespace-pre"}>
        <Spans spans={cell.band ? cell.spans : emphasis(cell.spans, palette)} />
      </span>
    </>
  );
  if (toggle === undefined) return <span className={clip ? "flex min-w-0 flex-1" : "flex flex-1"}>{body}</span>;
  return (
    <button
      type="button"
      className={`${clip ? "min-w-0" : ""} flex flex-1 cursor-pointer text-left`}
      onClick={() => onToggleFold(fileIndex, toggle)}
    >
      {body}
    </button>
  );
}

function UnifiedRow(props: ItemViewProps & { fileIndex: number; cell: UnifiedLineCell }) {
  const { cell, palette } = props;
  return (
    <div className="flex h-full" style={{ background: rowBackground(palette, cell), minWidth: "100%" }}>
      <Chevron {...props} />
      <LineNumber {...props} side="old" line={cell.oldLineNumber} />
      <LineNumber {...props} side="new" line={cell.newLineNumber} />
      <Content {...props} clip={false} />
    </div>
  );
}

function SplitHalf(props: ItemViewProps & { fileIndex: number; cell: SplitLineCell; side: Side }) {
  const { cell, palette, side } = props;
  return (
    <div className="flex h-full min-w-0 flex-1 overflow-hidden" style={{ background: rowBackground(palette, cell) }}>
      <Chevron {...props} />
      <LineNumber {...props} side={side} line={cell.lineNumber} />
      <Content {...props} clip />
    </div>
  );
}
