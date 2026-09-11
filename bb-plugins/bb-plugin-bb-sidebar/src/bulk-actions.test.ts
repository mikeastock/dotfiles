import { describe, expect, it } from "vitest";
import { runBulkAction } from "./bulk-actions";

describe("runBulkAction", () => {
  it("reports complete success in input order", async () => {
    const calls: string[] = [];
    const result = await runBulkAction(["a", "b", "c"], async (threadId) => {
      calls.push(threadId);
    });

    expect(calls).toHaveLength(3);
    expect(result).toEqual({
      succeededThreadIds: ["a", "b", "c"],
      failures: [],
    });
  });

  it("keeps successes and failures separate after a partial failure", async () => {
    const result = await runBulkAction(["a", "b", "c"], async (threadId) => {
      if (threadId === "b") throw new Error("offline");
    });

    expect(result).toEqual({
      succeededThreadIds: ["a", "c"],
      failures: [{ threadId: "b", error: "offline" }],
    });
  });

  it("caps concurrent work", async () => {
    let active = 0;
    let maximum = 0;
    await runBulkAction(
      ["a", "b", "c", "d", "e"],
      async () => {
        active += 1;
        maximum = Math.max(maximum, active);
        await Promise.resolve();
        active -= 1;
      },
      2,
    );
    expect(maximum).toBe(2);
  });
});
