import type { PluginSidebarThread } from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { StatusGlyph, hasStatusGlyph } from "./StatusGlyph";
import { relativeTimeLabel } from "./relative-time";

/**
 * The row's trailing slot: one fixed width, right-aligned, on every row.
 *
 * Fixed rather than intrinsic because the age label's width follows its text —
 * "now" is wider than "7m" — and an intrinsic slot drags whatever sits beside
 * it back and forth, so no two rows agree on a column. The width holds the
 * widest label this sidebar can produce ("now", "59m", "52w").
 */
export const STATUS_SLOT_CLASS = "flex w-7 shrink-0 items-center justify-end";

/**
 * The box every trailing glyph sits in, whatever its artwork measures.
 *
 * The status glyph, the provider glyph and a shelf's chevron all end a line at
 * the same inset, but they are drawn at different sizes. A shared box centres
 * each one on the same vertical axis, so right-aligning the boxes lines the
 * icons up instead of leaving them one or two pixels apart.
 */
export const TRAILING_GLYPH_BOX_CLASS =
  "flex size-3.5 shrink-0 items-center justify-center";

/**
 * How long a paused thread has been waiting, as the loudest mark this sidebar
 * draws.
 *
 * This is the one control allowed to break the fixed slot above. A blocked
 * thread is the only row in the list that cannot make progress without the
 * user, and in a list that never re-orders, the duration is the only staleness
 * signal there is — "waiting 45m" is a different sentence from "waiting 1m",
 * and neither can be told by position.
 *
 * The clock reads `latestAttentionAt`, bb's own "newest thing you have not
 * seen" timestamp. For a thread that is asking a question, that is the moment
 * it started asking. If bb ever bumps it for something that is not the
 * question, this number gets younger than the wait actually is — it never
 * reads older, so it cannot overstate the case.
 */
export function WaitingPill({
  thread,
  now,
}: {
  thread: PluginSidebarThread;
  /** Quantized clock, shared by every row in one render. */
  now: number;
}) {
  const waited = relativeTimeLabel(thread.latestAttentionAt, now);

  return (
    <span
      role="img"
      aria-label={`${thread.indicatorLabel ?? "Waiting for input"}, waiting ${waited}`}
      // Foreground is a fixed dark tint of the same hue rather than a theme
      // token: the fill is this orange in both themes, so the text has to be
      // dark in both, and `--foreground` flips.
      className="flex shrink-0 items-center gap-1 rounded-full bg-[color:var(--warning)] px-1.5 py-px text-2xs font-semibold tabular-nums text-[oklch(24%_0.04_50)]"
    >
      <Icon name="CircleQuestion" className="size-2.5" aria-hidden />
      {waited}
    </span>
  );
}

/**
 * Status OR age, never both: the glyph already implies the row is current, and
 * the age only earns its place once the thread has nothing to say.
 */
export function StatusOrTime({
  thread,
  now,
}: {
  thread: PluginSidebarThread;
  /** Quantized clock, shared by every row in one render. */
  now: number;
}) {
  if (hasStatusGlyph(thread.indicator)) {
    return (
      <StatusGlyph indicator={thread.indicator} label={thread.indicatorLabel} />
    );
  }
  return (
    <span className="tabular-nums text-2xs text-muted-foreground">
      {relativeTimeLabel(thread.updatedAt, now)}
    </span>
  );
}
