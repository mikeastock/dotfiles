import { describe, expect, it } from "vitest";
import {
  isInactiveThread,
  parseInactiveAfterHours,
} from "./inactive";

describe("inactive thread settings", () => {
  it("parses enabled whole-hour thresholds", () => {
    expect(parseInactiveAfterHours(true, "6")).toBe(6);
    expect(parseInactiveAfterHours(true, "24")).toBe(24);
  });

  it("disables classification for disabled or invalid settings", () => {
    expect(parseInactiveAfterHours(false, "6")).toBeNull();
    expect(parseInactiveAfterHours(true, "0")).toBeNull();
    expect(parseInactiveAfterHours(true, "1.5")).toBeNull();
    expect(parseInactiveAfterHours(true, "721")).toBeNull();
  });
});

describe("isInactiveThread", () => {
  const now = 10 * 60 * 60 * 1_000;

  it("moves a thread at the configured inactivity boundary", () => {
    expect(
      isInactiveThread(
        {
          createdAt: 0,
          updatedAt: now - 6 * 60 * 60 * 1_000,
          latestAttentionAt: 0,
        },
        now,
        6,
      ),
    ).toBe(true);
  });

  it("uses the newest creation, update, or attention timestamp", () => {
    expect(
      isInactiveThread(
        {
          createdAt: 0,
          updatedAt: now - 8 * 60 * 60 * 1_000,
          latestAttentionAt: now - 2 * 60 * 60 * 1_000,
        },
        now,
        6,
      ),
    ).toBe(false);
  });
});
