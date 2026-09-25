// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { safeSetItem } from "./safe-storage";

// Least critical first: a lost working-since stamp only restarts a duration
// label, so it goes before the lifecycle cache.
const working = "bb-sidebar:working-since:v1";
const order = "bb-sidebar:inbox-order-cache:v1";
const lifecycle = "bb-sidebar:lifecycle-cache:v1";
const children = "bb-sidebar:child-expansion:v1";
const shelves = "bb-sidebar:shelf-expansion:v1";
const sort = "bb-sidebar:active-sort:v1";
const settings = "bb-sidebar:settings-cache:v1";

function limitStorage(characters: number) {
  const setItem = Storage.prototype.setItem;
  vi.spyOn(Storage.prototype, "setItem").mockImplementation(function (
    this: Storage,
    key,
    value,
  ) {
    const size = Object.keys(this).reduce(
      (total, storedKey) =>
        total + (storedKey === key ? 0 : this.getItem(storedKey)!.length),
      value.length,
    );
    if (size > characters)
      throw new DOMException("Storage full", "QuotaExceededError");
    setItem.call(this, key, value);
  });
  return vi.spyOn(Storage.prototype, "removeItem");
}

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
});

describe("safe storage quota recovery", () => {
  it("preserves preferences when evicting the lifecycle cache is enough", () => {
    localStorage.setItem(lifecycle, "x".repeat(90));
    localStorage.setItem(sort, "project");
    localStorage.setItem(shelves, "{}");
    const remove = limitStorage(110);

    expect(safeSetItem(children, "x".repeat(20))).toBe(true);
    expect(remove.mock.calls).toEqual([[working], [order], [lifecycle]]);
    expect(localStorage.getItem(sort)).toBe("project");
    expect(localStorage.getItem(shelves)).toBe("{}");
  });

  it("evicts another cache only if the first eviction is insufficient", () => {
    localStorage.setItem(lifecycle, "x".repeat(20));
    localStorage.setItem(children, "x".repeat(20));
    localStorage.setItem(sort, "project");
    localStorage.setItem(shelves, "{}");
    const remove = limitStorage(50);

    expect(safeSetItem(settings, "x".repeat(30))).toBe(true);
    expect(remove.mock.calls).toEqual([[working], [order], [lifecycle], [children]]);
    expect(localStorage.getItem(sort)).toBe("project");
    expect(localStorage.getItem(shelves)).toBe("{}");
  });

  it("clears an unsavable target without touching bb core storage", () => {
    localStorage.setItem("bb.core.preference", "x".repeat(40));
    localStorage.setItem(children, "old");
    limitStorage(50);

    expect(safeSetItem(children, "x".repeat(100))).toBe(false);
    expect(localStorage.getItem(children)).toBeNull();
    expect(localStorage.getItem("bb.core.preference")).toBe("x".repeat(40));
  });

  it("does not evict data when storage is blocked for a non-quota reason", () => {
    const remove = vi.spyOn(Storage.prototype, "removeItem");
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("Storage blocked", "SecurityError");
    });
    expect(safeSetItem(children, "[]")).toBe(false);
    expect(remove).not.toHaveBeenCalled();
  });

  it("stops evicting if a retry fails for a non-quota reason", () => {
    localStorage.setItem(sort, "project");
    const remove = vi.spyOn(Storage.prototype, "removeItem");
    vi.spyOn(Storage.prototype, "setItem")
      .mockImplementationOnce(() => {
        throw new DOMException("Full", "QuotaExceededError");
      })
      .mockImplementation(() => {
        throw new DOMException("Blocked", "SecurityError");
      });

    expect(safeSetItem(children, "[]")).toBe(false);
    expect(remove.mock.calls).toEqual([[working]]);
    expect(localStorage.getItem(sort)).toBe("project");
  });
});
