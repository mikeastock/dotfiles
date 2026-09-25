import { describe, expect, it, vi } from "vitest";
import {
  configuredSnoozePresetError,
  canPark,
  formatSnoozeWakeTime,
  DEFAULT_SNOOZE_PRESET_CONFIG,
  nextWakeDelayMs,
  parseConfiguredSnoozePresets,
  resolveShelf,
  resolveWakeReason,
  resolveConfiguredSnoozePreset,
  snoozeWakeLabel,
  MAX_TIMEOUT_MS,
  type ThreadActivitySignals,
  type ThreadLifecycleRow,
} from "./lifecycle";

const quiet: ThreadActivitySignals = {
  hasPendingInteraction: false,
  isWorking: false,
  isUnread: false,
  latestAttentionAt: 0,
};

const row = (
  overrides: Partial<ThreadLifecycleRow> = {},
): ThreadLifecycleRow => ({
  threadId: "thr_1",
  settledAt: null,
  snoozedUntil: null,
  snoozedAt: null,
  ...overrides,
});

describe("canPark", () => {
  it("refuses while the agent is blocked on the user", () => {
    expect(canPark({ ...quiet, hasPendingInteraction: true })).toBe(false);
  });

  // The trap this whole feature has to avoid: bb has more kinds of live work
  // than a session status, and parking any of them hides running work.
  it("refuses while any work is running", () => {
    expect(canPark({ ...quiet, isWorking: true })).toBe(false);
  });

  it("allows a quiet thread", () => {
    expect(canPark(quiet)).toBe(true);
  });
});

describe("resolveShelf", () => {
  it("keeps an unparked thread active", () => {
    expect(resolveShelf(undefined, quiet, 1_000)).toBe("active");
  });

  it("settles a parked, quiet thread", () => {
    expect(resolveShelf(row({ settledAt: 500 }), quiet, 1_000)).toBe("settled");
  });

  it("brings a settled thread back when it starts working", () => {
    expect(
      resolveShelf(
        row({ settledAt: 500 }),
        { ...quiet, isWorking: true },
        1_000,
      ),
    ).toBe("active");
  });

  it("brings a settled thread back when it asks a question", () => {
    expect(
      resolveShelf(
        row({ settledAt: 500 }),
        { ...quiet, hasPendingInteraction: true },
        1_000,
      ),
    ).toBe("active");
  });

  it("un-settles on new attention after the settle", () => {
    expect(
      resolveShelf(
        row({ settledAt: 500 }),
        { ...quiet, latestAttentionAt: 900 },
        1_000,
      ),
    ).toBe("active");
  });

  it("keeps a snoozed thread hidden until its wake time", () => {
    expect(
      resolveShelf(row({ snoozedUntil: 2_000, snoozedAt: 500 }), quiet, 1_000),
    ).toBe("snoozed");
  });

  it("wakes a snoozed thread when the timer elapses", () => {
    expect(
      resolveShelf(row({ snoozedUntil: 900, snoozedAt: 500 }), quiet, 1_000),
    ).toBe("active");
  });

  // "Something happened" wakes it early — otherwise snooze hides the exact
  // thing the user needed to see.
  it("wakes a snoozed thread early when it raises its hand", () => {
    expect(
      resolveShelf(
        row({ snoozedUntil: 5_000, snoozedAt: 500 }),
        { ...quiet, hasPendingInteraction: true },
        1_000,
      ),
    ).toBe("active");
    expect(
      resolveShelf(
        row({ snoozedUntil: 5_000, snoozedAt: 500 }),
        { ...quiet, latestAttentionAt: 800 },
        1_000,
      ),
    ).toBe("active");
  });

  it("does not wake on activity that predates the snooze", () => {
    expect(
      resolveShelf(
        row({ snoozedUntil: 5_000, snoozedAt: 900 }),
        { ...quiet, latestAttentionAt: 800 },
        1_000,
      ),
    ).toBe("snoozed");
  });
});

describe("resolveWakeReason", () => {
  it("marks a timer wake and leaves a future snooze unmarked", () => {
    const snoozed = row({ snoozedUntil: 900, snoozedAt: 500 });
    expect(resolveWakeReason(snoozed, quiet, 1_000)).toBe("timer");
    expect(resolveWakeReason(snoozed, quiet, 800)).toBeNull();
  });

  it("marks new attention, including a pending interaction", () => {
    const snoozed = row({ snoozedUntil: 5_000, snoozedAt: 500 });
    expect(
      resolveWakeReason(
        snoozed,
        { ...quiet, latestAttentionAt: 800 },
        1_000,
      ),
    ).toBe("attention");
    expect(
      resolveWakeReason(
        snoozed,
        { ...quiet, hasPendingInteraction: true },
        1_000,
      ),
    ).toBe("attention");
  });
});

describe("snoozeWakeLabel", () => {
  it("rounds minutes up so a hidden thread never reads 0m", () => {
    expect(snoozeWakeLabel(1_000 + 1, 1_000)).toBe("1m");
    expect(snoozeWakeLabel(1_000 + 90_000, 1_000)).toBe("2m");
  });

  it("switches to hours and days", () => {
    expect(snoozeWakeLabel(1_000 + 2 * 3_600_000, 1_000)).toBe("2h");
    expect(snoozeWakeLabel(1_000 + 50 * 3_600_000, 1_000)).toBe("3d");
  });

  it("reads 'now' once the wake time has passed", () => {
    expect(snoozeWakeLabel(500, 1_000)).toBe("now");
  });
});

describe("formatSnoozeWakeTime", () => {
  it("includes the exact date and local time", () => {
    const wakeAt = Date.UTC(2026, 7, 23, 1, 30);
    expect(formatSnoozeWakeTime(wakeAt, "en-US", "UTC")).toBe(
      "Aug 23, 2026, 1:30 AM",
    );
  });
});

describe("resolveConfiguredSnoozePreset", () => {
  const resolve = (config: string, now: Date) =>
    resolveConfiguredSnoozePreset(parseConfiguredSnoozePresets(config)[0]!, now);

  it("offers the five default choices in the requested order", () => {
    const now = new Date(2026, 0, 5, 10);
    const presets = parseConfiguredSnoozePresets(DEFAULT_SNOOZE_PRESET_CONFIG);
    expect(presets.map((preset) => preset.label)).toEqual([
      "1 hour", "Wait refresh (5 hours)", "This evening", "Tomorrow morning", "Next week",
    ]);
    expect(presets.map((preset) => resolveConfiguredSnoozePreset(preset, now))).toEqual([
      new Date(2026, 0, 5, 11).getTime(),
      new Date(2026, 0, 5, 15).getTime(),
      new Date(2026, 0, 5, 18).getTime(),
      new Date(2026, 0, 6, 9).getTime(),
      new Date(2026, 0, 12, 9).getTime(),
    ]);
  });

  it("makes this evening unavailable at or after the configured time", () => {
    expect(resolve("evening@19:30", new Date(2026, 0, 5, 19, 29))).toBe(new Date(2026, 0, 5, 19, 30).getTime());
    expect(resolve("evening@19:30", new Date(2026, 0, 5, 19, 30))).toBeNull();
    expect(resolve("evening@19:30", new Date(2026, 0, 5, 23))).toBeNull();
  });

  it("uses editable calendar times and recalculates across midnight and year boundaries", () => {
    const preset = parseConfiguredSnoozePresets("Morning=tomorrow@08:15")[0]!;
    expect(resolveConfiguredSnoozePreset(preset, new Date(2026, 11, 31, 23, 59))).toBe(new Date(2027, 0, 1, 8, 15).getTime());
    expect(resolveConfiguredSnoozePreset(preset, new Date(2027, 0, 1, 0, 1))).toBe(new Date(2027, 0, 2, 8, 15).getTime());
    expect(resolve("next-week@10:30", new Date(2026, 0, 4, 23))).toBe(new Date(2026, 0, 5, 10, 30).getTime());
  });

  it.each([
    [2, 7, 23],
    [9, 31, 25],
  ])("preserves local morning through a DST change in month %i", (month, day, hours) => {
    vi.stubEnv("TZ", "America/New_York");
    try {
      const now = new Date(2026, month, day, 9);
      const wake = resolve("tomorrow", now)!;
      expect(new Date(wake).getHours()).toBe(9);
      expect(wake - now.getTime()).toBe(hours * 3_600_000);
      expect(resolve("1d", now)! - now.getTime()).toBe(24 * 3_600_000);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

  describe("parseConfiguredSnoozePresets", () => {
  it("parses durations and optional labels", () => {
    expect(parseConfiguredSnoozePresets("15m, Focus block=2.5h, 1d")).toEqual([
      { id: "preset-0", label: "15 minutes", durationMs: 15 * 60_000 },
      {
        id: "preset-1",
        label: "Focus block",
        durationMs: 2.5 * 3_600_000,
      },
      { id: "preset-2", label: "1 day", durationMs: 24 * 3_600_000 },
    ]);
  });

  it("skips invalid entries but keeps valid ones", () => {
    expect(parseConfiguredSnoozePresets("nope, 10m, 0m")).toEqual([
      { id: "preset-1", label: "10 minutes", durationMs: 10 * 60_000 },
    ]);
  });

  it("accepts editable calendar labels and times", () => {
    expect(parseConfiguredSnoozePresets("Tonight=evening@20:45, Morning=tomorrow@08:30, Monday=next-week@10:00")).toEqual([
      { id: "preset-0", label: "Tonight", calendar: "evening", hour: 20, minute: 45 },
      { id: "preset-1", label: "Morning", calendar: "tomorrow", hour: 8, minute: 30 },
      { id: "preset-2", label: "Monday", calendar: "next-week", hour: 10, minute: 0 },
    ]);
  });

  it.each(["tomorrow@24:00", "evening@18:60", "next-week@-1:00", "tomorrow@9", "tomorrow@09:00extra"])("rejects invalid calendar time %s", (value) => {
    expect(configuredSnoozePresetError(value)).not.toBeNull();
  });

    it("falls back to defaults when every entry is invalid", () => {
    expect(parseConfiguredSnoozePresets("later, eventually")).toEqual(
      parseConfiguredSnoozePresets(DEFAULT_SNOOZE_PRESET_CONFIG),
    );
    });

    it("reports settings that would silently fall back or discard entries", () => {
      expect(configuredSnoozePresetError("")).toBe(
        "Enter at least one snooze shortcut.",
      );
      expect(configuredSnoozePresetError("later")).toContain(
        "comma-separated durations",
      );
      expect(configuredSnoozePresetError("15m, later")).toContain(
        "comma-separated durations",
      );
      expect(
        configuredSnoozePresetError("1m,2m,3m,4m,5m,6m,7m,8m,9m"),
      ).toBe("Use no more than eight snooze shortcuts.");
      expect(configuredSnoozePresetError("15m, Lunch=3h")).toBeNull();
    });
});

describe("nextWakeDelayMs", () => {
  it("arms for the soonest upcoming wake", () => {
    expect(nextWakeDelayMs([5_000, 3_000, 9_000], 1_000)).toBe(2_050);
  });

  it("ignores wakes that have already passed", () => {
    expect(nextWakeDelayMs([500], 1_000)).toBeNull();
    expect(nextWakeDelayMs([], 1_000)).toBeNull();
  });

  // A far-future wake overflows setTimeout's signed 32-bit delay and fires
  // immediately, turning one snooze into a tight re-arm loop.
  it("clamps a far-future wake to the maximum timeout", () => {
    expect(nextWakeDelayMs([Number.MAX_SAFE_INTEGER], 0)).toBe(MAX_TIMEOUT_MS);
  });
});


describe("parked shelf", () => {
  it("waits indefinitely, including when already unread", () => {
    expect(resolveShelf(row({ parkedAt: 100 }), { ...quiet, isUnread: true }, 1e12)).toBe("parked");
  });
  it.each([
    { latestAttentionAt: 101 },
    { isWorking: true },
    { hasPendingInteraction: true },
  ])("returns to Active for fresh activity: %j", (signals) => {
    expect(resolveShelf(row({ parkedAt: 100 }), { ...quiet, ...signals }, 200)).toBe("active");
  });
});
