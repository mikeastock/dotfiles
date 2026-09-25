import { describe, expect, it } from "vitest";
import {
  movePinnedId,
  movePinnedIdByOffset,
  rebaseMovedId,
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

  it("rebases a move onto the global order without reordering hidden rows", () => {
    expect(rebaseMovedId(["a", "hidden", "b"], ["b", "a"], "a")).toEqual([
      "hidden",
      "b",
      "a",
    ]);
  });

  it("drops an anchor that disappeared mid-drag instead of reinstating it", () => {
    // Preview said "put A after B", but B is gone by the time it lands.
    expect(rebaseMovedId(["a", "c"], ["b", "a", "c"], "a")).toEqual(["a", "c"]);
  });

  it("keeps a reorder that landed elsewhere during the drag", () => {
    // The host swapped D and C while the pointer was down; only A moves.
    expect(
      rebaseMovedId(["a", "b", "d", "c"], ["b", "a", "c", "d"], "a"),
    ).toEqual(["b", "a", "d", "c"]);
  });

  it("leaves the order alone when the moved row is gone", () => {
    expect(rebaseMovedId(["b", "c"], ["b", "a", "c"], "a")).toEqual(["b", "c"]);
  });
});
