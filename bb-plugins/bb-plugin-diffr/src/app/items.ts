// Flatten a parsed diff into the rows the virtual list draws, honouring the
// panel's fold and file state.
import { defaultCollapsed } from "../vendor/diffr/document/regions";
import { rowsForFile, type Layout, type ViewerRow } from "../vendor/diffr/document/rows";
import type { Palette } from "../vendor/diffr/theme/palette";
import { filePath, fileVisibility, type DiffFile } from "../vendor/diffr/protocol/wire";
import type { DiffData } from "./model";

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
  /** Paths diffr hid by default that the user chose to load. */
  loaded: ReadonlySet<string>;
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

export function buildItems(data: DiffData, state: ViewState): Item[] {
  const items: Item[] = [];
  data.inventory.forEach((entry, fileIndex) => {
    const path = filePath(entry.file);
    items.push({ kind: "header", key: `${fileIndex}:header`, fileIndex });
    if (state.closed.has(path)) return;
    const failure = data.failures[fileIndex];
    if (failure !== undefined) {
      items.push({ kind: "note", key: `${fileIndex}:failure`, fileIndex, text: failure, tone: "error" });
      return;
    }
    const file = data.files[fileIndex];
    if (file === undefined) {
      items.push({ kind: "note", key: `${fileIndex}:missing`, fileIndex, text: "diffr sent no diff for this file", tone: "muted" });
      return;
    }
    const visibility = fileVisibility(file);
    if (visibility.collapsed && !state.loaded.has(path)) {
      items.push({
        kind: "note",
        key: `${fileIndex}:load`,
        fileIndex,
        text: `Load diff${visibility.label ? ` · ${visibility.label}` : ""}`,
        tone: "load",
      });
      return;
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
