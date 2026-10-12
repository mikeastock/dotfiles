import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";

/**
 * Muse 1.4 reports the subscription's own meters over MSP: `usage/changed` is
 * pushed the first time a host sees a model response and whenever the numbers
 * move, and `usage/read` returns the same payload on demand. Both describe the
 * last response the host received — a fresh `muse serve` that has made no model
 * call knows nothing — so a reading is captured from the hosts bb's threads
 * already run rather than bought with a probe request against the user's quota.
 */
export const MUSE_USAGE_CHANGED_METHOD = "usage/changed";

const WEEK_MS = 7 * 24 * 60 * 60 * 1_000;

const meterSchema = z
  .object({
    usedPercent: z.number(),
    resetsAtMs: z.number(),
  })
  .loose();

export const museSubscriptionUsageSchema = z
  .object({
    window: meterSchema.extend({ windowDurationMins: z.number().positive() }),
    weekly: meterSchema,
    tier: z.string(),
    observedAtMs: z.number(),
  })
  .loose();
export type MuseSubscriptionUsage = z.infer<typeof museSubscriptionUsageSchema>;

export function parseSubscriptionUsage(
  value: unknown,
): MuseSubscriptionUsage | null {
  const parsed = museSubscriptionUsageSchema.safeParse(value);
  return parsed.success ? parsed.data : null;
}

export type MuseUsageWindow = {
  label: string;
  usedPercent: number;
  resetsAt: string | null;
};

function windowLabel(minutes: number): string {
  if (minutes === 60) return "Hourly limit";
  if (minutes < 24 * 60 && minutes % 60 === 0) return `${minutes / 60}-hour limit`;
  if (minutes === 24 * 60) return "Daily limit";
  return `${minutes}-minute limit`;
}

function percent(value: number): number {
  return Math.min(100, Math.max(0, value));
}

/**
 * Turns a reading into bb usage windows as of `nowMs`. A reading outlives the
 * window it describes whenever no Muse thread has run since, so a meter whose
 * reset has passed is reported as spent-nothing rather than as the old number.
 * The weekly block turns over on a fixed boundary and rolls forward a week at
 * a time; the short window opens on the next request, so its reset is unknown
 * until one is made.
 */
export function museUsageWindows(
  usage: MuseSubscriptionUsage,
  nowMs: number,
): MuseUsageWindow[] {
  const windowLapsed = usage.window.resetsAtMs <= nowMs;
  let weeklyResetsAtMs = usage.weekly.resetsAtMs;
  const weeklyLapsed = weeklyResetsAtMs <= nowMs;
  while (weeklyResetsAtMs <= nowMs) {
    weeklyResetsAtMs += WEEK_MS;
  }
  return [
    {
      label: windowLabel(usage.window.windowDurationMins),
      usedPercent: windowLapsed ? 0 : percent(usage.window.usedPercent),
      resetsAt: windowLapsed
        ? null
        : new Date(usage.window.resetsAtMs).toISOString(),
    },
    {
      label: "Weekly limit",
      usedPercent: weeklyLapsed ? 0 : percent(usage.weekly.usedPercent),
      resetsAt: new Date(weeklyResetsAtMs).toISOString(),
    },
  ];
}

export interface MuseUsageStore {
  record(value: unknown): void;
  latest(): Promise<MuseSubscriptionUsage | null>;
}

/**
 * Keeps the newest reading in memory and on disk. Every thread runs its own
 * `muse serve`, and bb may run several bridge workers at once, so readings
 * arrive from many hosts and out of order; the arrival stamp decides which one
 * stands. The file is shared by every worker on the machine: whichever one
 * answers a usage request sees the reading another worker's thread received,
 * and a restarted bridge shows the meter before its first Muse turn.
 */
export function createMuseUsageStore(
  filePath: () => string | null,
): MuseUsageStore {
  let current: MuseSubscriptionUsage | null = null;
  let writing: Promise<void> = Promise.resolve();

  const newer = (
    left: MuseSubscriptionUsage | null,
    right: MuseSubscriptionUsage | null,
  ): MuseSubscriptionUsage | null => {
    if (left === null) return right;
    if (right === null) return left;
    return right.observedAtMs > left.observedAtMs ? right : left;
  };

  const readSaved = async (path: string): Promise<MuseSubscriptionUsage | null> => {
    try {
      return parseSubscriptionUsage(JSON.parse(await readFile(path, "utf8")));
    } catch {
      // Absent or unreadable: there is simply no saved reading.
      return null;
    }
  };

  const persist = (usage: MuseSubscriptionUsage): void => {
    const path = filePath();
    if (path === null) return;
    writing = writing
      .then(async () => {
        // Another worker may have saved a later reading since this one arrived.
        if (newer(await readSaved(path), usage) !== usage) return;
        await mkdir(dirname(path), { recursive: true });
        const temp = join(dirname(path), `.subscription-usage.${process.pid}.tmp`);
        await writeFile(temp, JSON.stringify(usage));
        await rename(temp, path);
      })
      .catch(() => {
        // A meter that cannot be saved is still served from memory.
      });
  };

  return {
    record(value) {
      const usage = parseSubscriptionUsage(value);
      if (usage === null || newer(current, usage) !== usage) return;
      current = usage;
      persist(usage);
    },
    async latest() {
      const path = filePath();
      if (path !== null) {
        current = newer(current, await readSaved(path));
      }
      return current;
    },
  };
}
