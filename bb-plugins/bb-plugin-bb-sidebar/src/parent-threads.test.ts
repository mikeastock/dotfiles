import { describe, expect, it } from "vitest";
import { parentCandidates } from "./parent-threads";

const thread = (id: string, projectId: string, parentThreadId: string | null = null, isArchived = false) =>
  ({ id, projectId, parentThreadId, isArchived });

describe("parent candidates", () => {
  it("offers threads from other projects", () => {
    const threads = [thread("a", "p1"), thread("b", "p1"), thread("c", "p2")];
    expect(parentCandidates(threads, threads[0]).map((candidate) => candidate.id)).toEqual(["b", "c"]);
  });

  it("excludes descendants across projects", () => {
    const threads = [thread("a", "p1"), thread("b", "p2", "a"), thread("c", "p1", "b"), thread("d", "p2")];
    expect(parentCandidates(threads, threads[0]).map((candidate) => candidate.id)).toEqual(["d"]);
  });

  it("keeps an archived current parent but hides other archived threads", () => {
    const threads = [thread("a", "p1", "b"), thread("b", "p2", null, true), thread("c", "p2", null, true)];
    expect(parentCandidates(threads, threads[0]).map((candidate) => candidate.id)).toEqual(["b"]);
  });
});
