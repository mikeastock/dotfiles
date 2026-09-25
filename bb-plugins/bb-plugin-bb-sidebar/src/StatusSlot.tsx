import type {
  PluginSidebarThread,
  PluginSidebarThreadIndicator,
} from "@get-bb/plugin-sdk/app";
import { cn } from "./lib/utils";
import { relativeTimeLabel } from "./relative-time";
import { useWorkingSinceContext } from "./useWorkingSince";
import { statusWithDuration } from "./working-since";

/**
 * The default trailing slot for cards and flat rows: fixed and right-aligned.
 *
 * Fixed rather than intrinsic because both ages and live-status labels vary in
 * width. The slot holds "Planning · 12m" without dragging the project column
 * back and forth as a thread changes state. Child trees override the width:
 * they carry no project column, so there the label's own width wins.
 */
export const STATUS_SLOT_CLASS = "flex w-20 shrink-0 items-center justify-end";

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
 * Status OR age, never both: the glyph already implies the row is current, and
 * the age only earns its place once the thread has nothing to say.
 *
 * A live status carries how long the work has run ("Working · 5m"), so the
 * slot answers "is it stuck?" as well as "what is it doing?".
 */
export function StatusOrTime({
  thread,
  now,
}: {
  thread: PluginSidebarThread;
  /** Quantized clock, shared by every row in one render. */
  now: number;
}) {
  const workingSince = useWorkingSinceContext();
  const status = threadShortStatus(thread);
  if (status !== null) {
    const label = shortStatusLabel(status, workingSince.get(thread.id), now);
    return (
      <span
        aria-label={
          thread.hasPendingInteraction ? label : (thread.indicatorLabel ?? label)
        }
        className={cn(
          "max-w-full truncate text-2xs font-medium",
          status.showsDuration && "tabular-nums",
          status.className,
        )}
      >
        {label}
      </span>
    );
  }
  return (
    <span className="tabular-nums text-2xs text-muted-foreground">
      {relativeTimeLabel(thread.updatedAt, now)}
    </span>
  );
}

export interface ShortStatus {
  label: string;
  className: string;
  /** Live work gets a running duration; a verdict or a request does not. */
  showsDuration: boolean;
}

export function shortStatus(
  indicator: PluginSidebarThreadIndicator,
  indicatorLabel: string | null,
): ShortStatus | null {
  const className = statusToneClass(indicator);
  switch (indicator) {
    case "unread-error":
      return { label: "Failed", className, showsDuration: false };
    case "waiting-for-input":
      return { label: "Needs you", className, showsDuration: false };
    case "unread-success":
      return { label: "Unread", className, showsDuration: false };
    case "runtime":
      return {
        label: isMonitoringLabel(indicatorLabel) ? "Monitoring" : "Working",
        className,
        showsDuration: true,
      };
    case "workflow":
      return { label: "Workflow", className, showsDuration: true };
    case "background-agent":
      return { label: "Agent", className, showsDuration: true };
    case "background-command":
      return { label: "Command", className, showsDuration: true };
    case "plan-mode":
      return { label: "Planning", className, showsDuration: true };
    case "goal":
      return { label: "Goal", className, showsDuration: true };
    case "draft":
      return { label: "Draft", className, showsDuration: false };
    case "working-draft":
      return { label: "Drafting", className, showsDuration: true };
    case "none":
      return null;
    default:
      return null;
  }
}

/** A pending user interaction outranks any concurrently reported runtime. */
export function threadShortStatus(
  thread: PluginSidebarThread,
): ShortStatus | null {
  return thread.hasPendingInteraction
    ? shortStatus("waiting-for-input", null)
    : shortStatus(thread.indicator, thread.indicatorLabel);
}

export function shortStatusLabel(
  status: ShortStatus,
  startedAt: number | undefined,
  now: number,
): string {
  return status.showsDuration
    ? statusWithDuration(status.label, startedAt, now)
    : status.label;
}

export function threadStatusLabel(
  thread: PluginSidebarThread,
  startedAt: number | undefined,
  now: number,
): string | null {
  const status = threadShortStatus(thread);
  return status === null ? null : shortStatusLabel(status, startedAt, now);
}

/**
 * A monitor is still a runtime, so the indicator keeps the usual spinner and
 * working duration. BB's accessible label carries the more precise state.
 */
function isMonitoringLabel(label: string | null): boolean {
  return label?.toLocaleLowerCase().includes("monitoring") ?? false;
}

/** Status palette shared by cards, child labels, and glyphs. */
export function statusToneClass(
  indicator: PluginSidebarThreadIndicator,
): string {
  switch (indicator) {
    case "unread-error":
      return "text-[color:var(--bb-sidebar-tone-error)]";
    case "waiting-for-input":
      return "text-[color:var(--bb-sidebar-tone-pending)]";
    case "unread-success":
      return "text-[color:var(--bb-sidebar-tone-success)]";
    case "runtime":
    case "workflow":
    case "background-agent":
    case "background-command":
    case "plan-mode":
    case "goal":
      return "text-[color:var(--bb-sidebar-tone-working)]";
    case "draft":
    case "working-draft":
      return "text-[color:var(--bb-sidebar-tone-draft)]";
    case "none":
    default:
      return "text-muted-foreground";
  }
}
