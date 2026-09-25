import { describe, expect, it } from "vitest";
import {
  describeReclaim,
  planTerminalReclaim,
  type ReclaimTerminal,
} from "./reclaim";

function terminal(overrides: Partial<ReclaimTerminal> = {}): ReclaimTerminal {
  return {
    id: "term_1",
    lastUserInputAt: null,
    status: "running",
    ...overrides,
  };
}

describe("planTerminalReclaim", () => {
  it("closes only the terminals nobody typed in", () => {
    expect(
      planTerminalReclaim([
        terminal({ id: "term_untouched" }),
        terminal({ id: "term_used", lastUserInputAt: 1 }),
      ]),
    ).toEqual({ close: ["term_untouched"], keep: 1 });
  });

  it("ignores terminals that are already gone", () => {
    expect(
      planTerminalReclaim([
        terminal({ id: "term_exited", status: "exited" }),
        terminal({ id: "term_disconnected", status: "disconnected" }),
      ]),
    ).toEqual({ close: [], keep: 0 });
  });

  it("counts a starting terminal as live", () => {
    expect(
      planTerminalReclaim([
        terminal({ id: "term_starting", status: "starting", lastUserInputAt: 1 }),
      ]),
    ).toEqual({ close: [], keep: 1 });
  });

  it("plans nothing for a thread with no terminals", () => {
    expect(planTerminalReclaim([])).toEqual({ close: [], keep: 0 });
  });
});

describe("describeReclaim", () => {
  it("says nothing when settling released nothing", () => {
    expect(
      describeReclaim({
        closedTerminals: 0,
        keptTerminals: 0,
        stoppedRuntime: false,
      }),
    ).toBeUndefined();
  });

  it("reports the runtime alone when there were no terminals", () => {
    expect(
      describeReclaim({
        closedTerminals: 0,
        keptTerminals: 0,
        stoppedRuntime: true,
      }),
    ).toBe("Agent session stopped");
  });

  it("names what was closed and what was left", () => {
    expect(
      describeReclaim({
        closedTerminals: 1,
        keptTerminals: 2,
        stoppedRuntime: true,
      }),
    ).toBe(
      "Agent session stopped · closed 1 terminal nobody used · 2 terminals left running",
    );
  });

  it("warns about surviving terminals even when nothing was closed", () => {
    expect(
      describeReclaim({
        closedTerminals: 0,
        keptTerminals: 1,
        stoppedRuntime: false,
      }),
    ).toBe("1 terminal left running");
  });
});
