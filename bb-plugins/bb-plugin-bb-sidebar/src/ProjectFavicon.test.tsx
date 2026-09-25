// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render } from "@testing-library/react";
import { ProjectFavicon } from "./ProjectFavicon";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("ProjectFavicon", () => {
  it("retries an icon that failed to load instead of hiding it for good", () => {
    vi.useFakeTimers();
    const src = "/project-icon?projectId=proj_retry&revision=0";
    const view = render(<ProjectFavicon src={src} fallback="F" />);

    const first = view.container.querySelector("img")!;
    expect(first.getAttribute("src")).toBe(src);
    fireEvent.error(first);
    expect(view.container.querySelector("img")).toBeNull();
    expect(view.container.textContent).toBe("F");

    act(() => {
      vi.advanceTimersByTime(15_000);
    });
    const retry = view.container.querySelector("img")!;
    expect(retry.getAttribute("src")).toBe(`${src}&attempt=1`);
    fireEvent.load(retry);

    const icon = view.container.querySelector("img.object-contain")!;
    expect(icon.getAttribute("src")).toBe(`${src}&attempt=1`);
  });
});
