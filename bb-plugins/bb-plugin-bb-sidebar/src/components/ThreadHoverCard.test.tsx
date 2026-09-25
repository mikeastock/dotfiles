// @vitest-environment jsdom
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ThreadHoverCard } from "./ThreadHoverCard";

function Card() {
  const [open, setOpen] = useState(false);
  return <ThreadHoverCard open={open} onOpenChange={setOpen} content={<a href="#port">Port</a>}><a href="#thread">Thread</a></ThreadHoverCard>;
}
afterEach(() => { cleanup(); vi.useRealTimers(); });

it("stays open over blank card space and closes once the pointer leaves both regions", async () => {
  vi.useFakeTimers();
  render(<Card />);
  const row = screen.getByRole("link", { name: "Thread" });
  fireEvent.pointerMove(row);
  await act(async () => { await vi.advanceTimersByTimeAsync(260); });
  const panel = screen.getByRole("dialog");
  expect(screen.getByRole("link", { name: "Thread", description: "Port" })).toBe(row);
  vi.spyOn(panel, "getBoundingClientRect").mockReturnValue({ left: 100, right: 350, top: 0, bottom: 300 } as DOMRect);
  fireEvent.pointerLeave(row);
  fireEvent(document, new MouseEvent("pointermove", { clientX: 200, clientY: 150, bubbles: true }));
  await act(async () => { await vi.advanceTimersByTimeAsync(400); });
  expect(screen.getByRole("dialog")).toBe(panel);
  fireEvent(document, new MouseEvent("pointermove", { clientX: 500, clientY: 500, bubbles: true }));
  await act(async () => { await vi.advanceTimersByTimeAsync(400); });
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("does not open from pointer focus or a click", () => {
  render(<Card />);
  const row = screen.getByRole("link", { name: "Thread" });
  fireEvent.pointerDown(row);
  act(() => row.focus());
  expect(screen.queryByRole("dialog")).toBeNull();
  fireEvent.pointerUp(document);
  fireEvent.click(row);
  expect(screen.queryByRole("dialog")).toBeNull();
});

it("cancels dismissal when the pointer re-enters the row", async () => {
  vi.useFakeTimers();
  render(<Card />);
  const row = screen.getByRole("link", { name: "Thread" });
  fireEvent.pointerMove(row);
  await act(async () => { await vi.advanceTimersByTimeAsync(260); });
  fireEvent.pointerLeave(row);
  fireEvent.pointerMove(row);
  await act(async () => { await vi.advanceTimersByTimeAsync(400); });
  expect(screen.getByRole("dialog")).toBeDefined();
});

function ExpandableCard({ name }: { name: string }) {
  const [open, setOpen] = useState(false);
  const [expanded, setExpanded] = useState(false);
  return <ThreadHoverCard open={open} onOpenChange={setOpen} content={<>
    <button type="button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>Subthreads for {name}</button>
    {expanded ? <span>Child of {name}</span> : null}
  </>}><a href={`#${name}`}>{name}</a></ThreadHoverCard>;
}

it.each([false, true])("replaces a focused expanded card without restoring old focus, keyboard=%s", async (keyboard) => {
  vi.useFakeTimers();
  render(<><ExpandableCard name="First" /><ExpandableCard name="Second" /></>);
  const first = screen.getByRole("link", { name: "First" });
  if (keyboard) {
    act(() => first.focus());
    fireEvent.keyDown(first, { key: "Tab" });
  } else {
    fireEvent.pointerMove(first);
    await act(async () => { await vi.advanceTimersByTimeAsync(260); });
  }
  const toggle = screen.getByRole("button", { name: "Subthreads for First" });
  act(() => toggle.focus());
  fireEvent.click(toggle);
  expect(screen.getByText("Child of First")).toBeDefined();
  const second = screen.getByRole("link", { name: "Second" });
  fireEvent.pointerLeave(first);
  fireEvent.pointerMove(second);
  await act(async () => { await vi.advanceTimersByTimeAsync(400); });
  expect(screen.getAllByRole("dialog")).toHaveLength(1);
  expect(screen.queryByRole("button", { name: "Subthreads for First" })).toBeNull();
  expect(screen.getByRole("button", { name: "Subthreads for Second" })).toBeDefined();
  expect(document.activeElement).not.toBe(first);
});
