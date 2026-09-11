import { describe, expect, it } from "vitest";
import {
  movePinnedId,
  movePinnedIdByOffset,
  mergeVisibleOrder,
  orderInboxThreads,
  orderPinnedThreads,
  pinnedNeighbors,
} from "./pinned-order";

describe("pinned ordering", () => {
  it("moves before and after another pinned thread", () => {
    expect(movePinnedId(["a", "b", "c"], "c", "a", "before")).toEqual([
      "c",
      "a",
      "b",
    ]);
    expect(movePinnedId(["a", "b", "c"], "a", "c", "after")).toEqual([
      "b",
      "c",
      "a",
    ]);
  });

  it("moves one keyboard step and stops at either edge", () => {
    expect(movePinnedIdByOffset(["a", "b", "c"], "b", -1)).toEqual([
      "b",
      "a",
      "c",
    ]);
    expect(movePinnedIdByOffset(["a", "b", "c"], "b", 1)).toEqual([
      "a",
      "c",
      "b",
    ]);
    expect(movePinnedIdByOffset(["a", "b"], "a", -1)).toEqual(["a", "b"]);
  });

  it("derives the final neighbors expected by the backend", () => {
    expect(pinnedNeighbors(["c", "a", "b"], "c")).toEqual({
      previousThreadId: null,
      nextThreadId: "a",
    });
    expect(pinnedNeighbors(["c", "a", "b"], "a")).toEqual({
      previousThreadId: "c",
      nextThreadId: "b",
    });
  });

  it("orders visible rows from a global pinned id list", () => {
    const rows = [{ id: "a" }, { id: "b" }, { id: "c" }];
    expect(orderPinnedThreads(rows, ["hidden", "c", "a", "b"])).toEqual([
      { id: "c" },
      { id: "a" },
      { id: "b" },
    ]);
  });

  it("keeps new inbox rows above the durable custom order", () => {
    const rows = [{ id: "new" }, { id: "a" }, { id: "b" }];
    expect(orderInboxThreads(rows, ["b", "a"])).toEqual([
      { id: "new" },
      { id: "b" },
      { id: "a" },
    ]);
  });

  it("reorders a project-scoped subset without moving hidden rows", () => {
    expect(
      mergeVisibleOrder(["a", "hidden", "b"], ["b", "a"]),
    ).toEqual(["b", "hidden", "a"]);
  });
});
