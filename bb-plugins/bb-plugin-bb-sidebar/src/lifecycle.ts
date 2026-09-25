import type { PluginSidebarThread } from "@get-bb/plugin-sdk";

/**
 * The parked / settled / snoozed lifecycle, as pure functions over stored rows.
 *
 * This state lives in the PLUGIN's own database, never on bb's thread. That
 * keeps a plugin concept out of bb's schema and out of the host-daemon
 * protocol, and uninstalling the plugin takes its state with it.
 */

export interface ThreadLifecycleRow {
  threadId: string;
  /** When the user parked it to wait on someone else. */
  parkedAt?: number | null;
  /** When the user settled it; null when it is active. */
  settledAt: number | null;
  /** Explicit user choice. Null or absent means policy-owned state. */
  settledOverride?: "active" | "settled" | null;
  /** Wake time for a snooze; null when it is not snoozed. */
  snoozedUntil: number | null;
  /** When the snooze was set — used to detect activity since. */
  snoozedAt: number | null;
}

/** The activity signals that outrank a user's parking decision. */
export interface ThreadActivitySignals {
  hasPendingInteraction: boolean;
  /** Any live work: runtime, workflows, background agents, plan, goals. */
  isWorking: boolean;
  isUnread: boolean;
  /** Newest attention timestamp bb reports for the thread. */
  latestAttentionAt: number;
}

export type ThreadShelf = "active" | "parked" | "snoozed" | "settled";
export type WakeReason = "timer" | "attention";

/**
 * Why a snoozed thread is back in the active inbox, if it has woken at all.
 *
 * The lifecycle row deliberately remains until acknowledgement. That makes
 * the Woke marker durable across reloads and gives every client the same
 * answer. A pending interaction is attention even if bb has not advanced the
 * rolled-up timestamp yet.
 */
export function resolveWakeReason(
  row: ThreadLifecycleRow | undefined,
  signals: ThreadActivitySignals,
  now: number,
): WakeReason | null {
  if (row?.snoozedUntil === null || row?.snoozedUntil === undefined) {
    return null;
  }

  const wokeOnAttention =
    signals.hasPendingInteraction ||
    (row.snoozedAt !== null && signals.latestAttentionAt > row.snoozedAt);
  if (wokeOnAttention) return "attention";
  return row.snoozedUntil <= now ? "timer" : null;
}

/**
 * Whether a thread may be parked at all.
 *
 * bb has more kinds of live work than a single session status — workflows,
 * background agents, background commands, plan mode, goals — and every one of
 * them must block parking. Hiding a thread that is still working is the one
 * failure this feature cannot afford.
 */
export function canPark(signals: ThreadActivitySignals): boolean {
  return !signals.hasPendingInteraction && !signals.isWorking;
}

/** Any live work at all, which blocks parking and wakes a parked thread. */
export function isThreadWorking(thread: PluginSidebarThread): boolean {
  const { activity } = thread;
  return (
    activity.workflows > 0 ||
    activity.backgroundAgents > 0 ||
    activity.backgroundCommands > 0 ||
    activity.planMode > 0 ||
    activity.goals > 0 ||
    thread.indicator === "runtime" ||
    thread.indicator === "working-draft"
  );
}

/** Whether a sidebar thread is idle enough for archive and parking actions. */
export function canParkThread(thread: PluginSidebarThread): boolean {
  return canPark({
    hasPendingInteraction: thread.hasPendingInteraction,
    isWorking: isThreadWorking(thread),
    isUnread: thread.isUnread,
    latestAttentionAt: thread.latestAttentionAt,
  });
}

/**
 * Which shelf a thread belongs on right now.
 *
 * Order matters. Live work and a raised hand always win, so a parked thread
 * that starts working or asks a question comes straight back. Then snooze,
 * because a wake time is a stronger statement than a settle. Then settled.
 */
export function resolveShelf(
  row: ThreadLifecycleRow | undefined,
  signals: ThreadActivitySignals,
  now: number,
): ThreadShelf {
  if (row === undefined) return "active";
  if (!canPark(signals)) return "active";

  if (row.parkedAt != null) {
    return signals.latestAttentionAt > row.parkedAt ? "active" : "parked";
  }

  if (row.snoozedUntil !== null) {
    if (resolveWakeReason(row, signals, now) === null) return "snoozed";
    return "active";
  }

  if (row.settledAt !== null) {
    // New attention since the settle un-settles it: the thread has more to
    // say than it did when the user filed it away.
    if (signals.latestAttentionAt > row.settledAt) return "active";
    return "settled";
  }

  return "active";
}

const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
const WEEK_MS = 7 * DAY_MS;

export const DEFAULT_SNOOZE_PRESET_CONFIG =
  "1h, Wait refresh (5 hours)=5h, evening@18:00, tomorrow@09:00, next-week@09:00";

type CalendarSnoozeDay = "evening" | "tomorrow" | "next-week";

export type ConfiguredSnoozePreset = {
  id: string;
  label: string;
} & (
  | { durationMs: number }
  | { calendar: CalendarSnoozeDay; hour: number; minute: number }
);

export function configuredSnoozePresetError(configured: string): string | null {
  const entries = configured
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  if (entries.length === 0) return "Enter at least one snooze shortcut.";
  if (entries.length > 8) return "Use no more than eight snooze shortcuts.";
  if (parseSnoozePresetEntries(configured).length !== entries.length) {
    return "Use comma-separated durations or calendar times, such as 1h, Wait refresh=5h, evening@18:00, tomorrow@09:00, or next-week@09:00.";
  }
  return null;
}

const DURATION_UNIT_MS = {
  m: MINUTE_MS,
  h: HOUR_MS,
  d: DAY_MS,
  w: WEEK_MS,
} as const;

const DURATION_UNIT_LABEL = {
  m: "minute",
  h: "hour",
  d: "day",
  w: "week",
} as const;

/**
 * Parse durations and local calendar times, with optional custom labels.
 *
 * At most eight presets are shown. Durations range from one minute to one
 * year. A wholly invalid setting falls back to the defaults, so a typo cannot
 * remove Snooze from every context menu.
 */
function parseSnoozePresetEntries(source: string): ConfiguredSnoozePreset[] {
  return source
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .slice(0, 8)
    .flatMap<ConfiguredSnoozePreset>((part, index) => {
      const separator = part.indexOf("=");
      const customLabel = separator >= 0 ? part.slice(0, separator).trim() : "";
      const value = (separator >= 0 ? part.slice(separator + 1) : part)
        .trim()
        .toLowerCase();
      const calendar =
        /^(evening|tomorrow|next-week)(?:@(\d{1,2}):(\d{2}))?$/.exec(value);
      if (calendar) {
        const day = calendar[1] as CalendarSnoozeDay;
        const defaultHour = day === "evening" ? 18 : 9;
        const hour = Number(calendar[2] ?? defaultHour);
        const minute = Number(calendar[3] ?? 0);
        if (hour > 23 || minute > 59) return [];
        const labels: Record<CalendarSnoozeDay, string> = {
          evening: "This evening",
          tomorrow: "Tomorrow morning",
          "next-week": "Next week",
        };
        return [
          {
            id: `preset-${index}`,
            label: customLabel.slice(0, 40) || labels[day],
            calendar: day,
            hour,
            minute,
          },
        ];
      }
      const match = /^(\d+(?:\.\d+)?)\s*([mhdw])$/.exec(value);
      if (!match) return [];

      const amount = Number(match[1]);
      const unit = match[2] as keyof typeof DURATION_UNIT_MS;
      const durationMs = amount * DURATION_UNIT_MS[unit];
      if (
        !Number.isFinite(durationMs) ||
        durationMs < MINUTE_MS ||
        durationMs > 365 * DAY_MS
      ) {
        return [];
      }

      const displayedAmount = Number.isInteger(amount)
        ? String(amount)
        : String(Number(amount.toFixed(2)));
      const generatedLabel = `${displayedAmount} ${DURATION_UNIT_LABEL[unit]}${amount === 1 ? "" : "s"}`;
      return [
        {
          id: `preset-${index}`,
          label: customLabel.slice(0, 40) || generatedLabel,
          durationMs,
        },
      ];
    });
}

export function parseConfiguredSnoozePresets(
  configured: string,
): ConfiguredSnoozePreset[] {
  const parsed = parseSnoozePresetEntries(configured);
  return parsed.length > 0
    ? parsed
    : parseSnoozePresetEntries(DEFAULT_SNOOZE_PRESET_CONFIG);
}

/**
 * Compact "wakes in" label: "5m", "2h", "3d". Minutes round up so a snooze
 * never reads "0m" while the thread is still hidden.
 */
export function snoozeWakeLabel(snoozedUntil: number, now: number): string {
  const remaining = snoozedUntil - now;
  if (remaining <= 0) return "now";
  if (remaining < HOUR_MS) {
    return `${Math.max(1, Math.ceil(remaining / MINUTE_MS))}m`;
  }
  if (remaining < DAY_MS) return `${Math.ceil(remaining / HOUR_MS)}h`;
  return `${Math.ceil(remaining / DAY_MS)}d`;
}

/** Full local wake time for confirmation feedback after a snooze. */
export function formatSnoozeWakeTime(
  snoozedUntil: number,
  locale?: string,
  timeZone?: string,
): string {
  return new Intl.DateTimeFormat(locale, {
    dateStyle: "medium",
    timeStyle: "short",
    ...(timeZone ? { timeZone } : {}),
  }).format(new Date(snoozedUntil));
}

/**
 * Resolve at selection time so a menu opened before midnight never uses a
 * stale date. Calendar times follow the selecting device's local timezone.
 * An evening that has passed is unavailable, rather than silently tomorrow.
 */
export function resolveConfiguredSnoozePreset(
  preset: ConfiguredSnoozePreset,
  now = new Date(),
): number | null {
  if ("durationMs" in preset) return now.getTime() + preset.durationMs;

  const addDays = preset.calendar === "next-week"
    ? (1 - now.getDay() + 7) % 7 || 7
    : preset.calendar === "tomorrow" ? 1 : 0;
  const wake = new Date(now);
  // Use calendar-day arithmetic to preserve the local hour across DST.
  wake.setDate(wake.getDate() + addDays);
  wake.setHours(preset.hour, preset.minute, 0, 0);
  return wake.getTime() > now.getTime() ? wake.getTime() : null;
}

/**
 * `setTimeout` delays are signed 32-bit: a far-future wake overflows and fires
 * immediately, which turns one snooze into a tight re-arm loop. Clamped, the
 * timer simply re-arms every ~24.8 days until the wake is in range.
 */
export const MAX_TIMEOUT_MS = 2_147_483_647;

export function nextWakeDelayMs(
  snoozedUntilValues: readonly number[],
  now: number,
): number | null {
  const upcoming = snoozedUntilValues.filter((value) => value > now);
  if (upcoming.length === 0) return null;
  const soonest = Math.min(...upcoming);
  return Math.min(Math.max(0, soonest - now) + 50, MAX_TIMEOUT_MS);
}
