// Flatten a parsed diff into the rows the virtual list draws, honouring the
// panel's fold and file state.
import { defaultCollapsed } from "../vendor/diffr/document/regions";
import { rowsForFile, type Layout, type ViewerRow } from "../vendor/diffr/document/rows";
import type { Palette } from "../vendor/diffr/theme/palette";
import { filePath, type DiffFile } from "../vendor/diffr/protocol/wire";
import type { FileRecord } from "../contract";
import type { DiffData, Loads } from "./model";

export type Item =
  | { kind: "header"; key: string; fileIndex: number }
  | { kind: "row"; key: string; fileIndex: number; row: ViewerRow }
  | { kind: "note"; key: string; fileIndex: number; text: string; tone: "muted" | "error" | "load" };

/** Row geometry. Touch screens get rows and chevrons big enough to tap (24px minimum). */
export interface Metrics {
  row: number;
  header: number;
  chevron: number;
}
export const FINE_METRICS: Metrics = { row: 20, header: 32, chevron: 16 };
export const COARSE_METRICS: Metrics = { row: 28, header: 40, chevron: 28 };

export const itemHeight = (item: Item, metrics: Metrics) => (item.kind === "header" ? metrics.header : metrics.row);

export interface ViewState {
  layout: Layout;
  palette: Palette;
  /** Collapsed fold-state ids per file index, once the user has toggled one. */
  folds: ReadonlyMap<number, ReadonlySet<number>>;
  /** Paths the user closed to their header. */
  closed: ReadonlySet<string>;
  /** Paths the user chose to load: files diffr hid, and files too large to load unasked. */
  requested: ReadonlySet<string>;
}

/** Records up to this size load as soon as diffr finishes; larger ones wait for a click. */
export const AUTO_LOAD_BYTES = 8 * 1024 * 1024;

const megabytes = (bytes: number) => `${(bytes / 1024 / 1024).toFixed(1)} MB`;

/** Whether the panel should read this file's record now. */
export function wantsRecord(record: FileRecord | null, path: string, requested: ReadonlySet<string>): boolean {
  if (record === null || record.summary.kind !== "text") return false;
  if (requested.has(path)) return true;
  return !record.summary.hidden.collapsed && record.length <= AUTO_LOAD_BYTES;
}

const defaults = new WeakMap<DiffFile, ReadonlySet<number>>();

/** The collapsed ids in effect for a file: the user's, else diffr's defaults. */
export function foldsFor(file: DiffFile, fileIndex: number, folds: ViewState["folds"]): ReadonlySet<number> {
  const chosen = folds.get(fileIndex);
  if (chosen !== undefined) return chosen;
  let initial = defaults.get(file);
  if (initial === undefined) {
    initial = file.diff.type === "text" ? defaultCollapsed(file.diff) : new Set();
    defaults.set(file, initial);
  }
  return initial;
}

/** rowsForFile is the expensive step; reuse it while nothing it reads changed. */
const rowCache = new WeakMap<
  DiffFile,
  { layout: Layout; palette: Palette; collapsed: ReadonlySet<number>; rows: ViewerRow[] }
>();

function cachedRows(file: DiffFile, fileIndex: number, layout: Layout, palette: Palette, collapsed: ReadonlySet<number>) {
  const cached = rowCache.get(file);
  if (cached && cached.layout === layout && cached.palette === palette && cached.collapsed === collapsed) {
    return cached.rows;
  }
  // The first row is diffr's file header; the panel draws its own.
  const rows = rowsForFile(file, fileIndex, layout, palette, collapsed).slice(1);
  rowCache.set(file, { layout, palette, collapsed, rows });
  return rows;
}

export function buildItems(data: DiffData, loads: Loads, state: ViewState): Item[] {
  const items: Item[] = [];
  data.inventory.forEach((entry, fileIndex) => {
    const path = filePath(entry.file);
    const note = (key: string, text: string, tone: "muted" | "error" | "load") =>
      items.push({ kind: "note", key: `${fileIndex}:${key}`, fileIndex, text, tone });
    items.push({ kind: "header", key: `${fileIndex}:header`, fileIndex });
    if (state.closed.has(path)) return;
    const record = data.records[fileIndex] ?? null;
    if (record === null) return void note("missing", "diffr sent no diff for this file", "muted");
    const { summary } = record;
    if (summary.kind === "error") return void note("error", summary.message, "error");
    if (summary.kind === "binary") return void note("binary", "Binary file", "muted");
    const file = loads.files.get(fileIndex);
    if (file === undefined) {
      const failure = loads.failures.get(fileIndex);
      if (failure !== undefined) {
        note("failure", failure, "error");
        return void note("load", "Try loading again", "load");
      }
      if (wantsRecord(record, path, state.requested)) return void note("loading", "Loading…", "muted");
      const reasons = [
        summary.hidden.collapsed ? summary.hidden.label || "Hidden by default" : null,
        record.length > AUTO_LOAD_BYTES ? `large diff, ${megabytes(record.length)}` : null,
      ].filter((reason) => reason !== null);
      return void note("load", `Load diff · ${reasons.join(" · ")}`, "load");
    }
    const collapsed = foldsFor(file, fileIndex, state.folds);
    for (const row of cachedRows(file, fileIndex, state.layout, state.palette, collapsed)) {
      if (row.label !== undefined && row.left === undefined && row.cell === undefined) {
        items.push({ kind: "note", key: row.key, fileIndex, text: row.label, tone: "muted" });
      } else {
        items.push({ kind: "row", key: row.key, fileIndex, row });
      }
    }
  });
  return items;
}
