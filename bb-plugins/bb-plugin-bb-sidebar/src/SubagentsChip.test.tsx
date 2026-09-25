// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";

const app = await loadPluginApp(() => import("../app"));
const childrenChip = app.threadHeaderActions.find(
  (slot) => slot.id === "children",
)!;

function thread(
  overrides: Partial<PluginSidebarThread> = {},
): PluginSidebarThread {
  return {
    id: "thr_1",
    projectId: "proj_1",
    title: "A thread",
    titleFallback: null,
    parentThreadId: null,
    sectionId: null,
    originKind: null,
    originPluginId: null,
    providerId: "codex",
    hasPendingInteraction: false,
    activity: {
      workflows: 0,
      backgroundAgents: 0,
      backgroundCommands: 0,
      planMode: 0,
      goals: 0,
    },
    indicator: "none",
    indicatorLabel: null,
    isUnread: false,
    isPinned: false,
    isArchived: false,
    environment: null,
    host: null,
    createdAt: 100,
    updatedAt: 100,
    lastReadAt: 100,
    latestAttentionAt: 100,
    ...overrides,
  };
}

afterEach(cleanup);

describe("SubagentsChip", () => {
  it.each([false, true])("loads execution details only on hover and handles failure=%s", async (fail) => {
    let requests = 0;
    renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "child", title: "Child", parentThreadId: "parent" })],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          getThreadExecutionDetails: (input) => {
            expect(input).toEqual({ threadId: "child" });
            requests++;
            if (fail) throw new Error("Offline");
            return { model: "gpt-6", reasoningLevel: "high" };
          },
        },
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "1 child thread" }));
    expect(requests).toBe(0);
    const row = screen.getByRole("button", { name: "Open child thread: Child" });
    fireEvent.pointerMove(row, { pointerType: "mouse" });
    await waitFor(() => {
      const tooltip = screen.getByRole("dialog", { name: "Thread details" });
      expect(tooltip.textContent).toContain("Provider: codex");
      expect(tooltip.textContent).toContain(fail ? "Model: Unavailable" : "Model: gpt-6");
      if (!fail) expect(tooltip.textContent).toContain("Reasoning: high");
    });
    expect(requests).toBe(1);
  });

  it.each(["child", "grandchild"])("renames a %s without opening it and keeps the popup on cancel", async (targetId) => {
    const rendered = renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({ id: "child", title: "Child", parentThreadId: "parent" }),
            thread({ id: "grandchild", title: "Grandchild", parentThreadId: "child" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "1 child thread" }));
    if (targetId === "grandchild") {
      fireEvent.click(screen.getByRole("button", { name: "Show 1 grandchild thread for Child" }));
    }
    const title = targetId === "child" ? "Child" : "Grandchild";
    const startRename = async () => {
      fireEvent.contextMenu(screen.getByRole("button", { name: `Open ${targetId} thread: ${title}` }));
      fireEvent.click(within(await screen.findByRole("menu", { name: "Thread actions" })).getByText("Rename"));
      return screen.findByRole("textbox", { name: `Rename ${title}` });
    };
    let input = await startRename();
    expect(input.closest("button")).toBeNull();
    fireEvent.change(input, { target: { value: "Canceled" } });
    fireEvent.keyDown(input, { key: "Escape" });
    expect(screen.getByRole("region", { name: "Child threads" })).toBeTruthy();
    expect(rendered.sidebarActionCalls).toEqual([]);

    input = await startRename();
    fireEvent.change(input, { target: { value: "Renamed child" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(rendered.sidebarActionCalls).toEqual([
      { method: "rename", threadId: targetId, title: "Renamed child" },
    ]));
  });

  it("mounts the shared child list in the header menu", () => {
    const rendered = renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({
              id: "child-a",
              title: "Child A",
              parentThreadId: "parent",
              createdAt: 101,
            }),
            thread({
              id: "child-b",
              title: "Child B",
              parentThreadId: "parent",
              createdAt: 102,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
      },
    );

    const trigger = screen.getByRole("button", { name: "2 child threads" });
    fireEvent.click(trigger);
    const popup = screen.getByRole("region", { name: "Child threads" });
    expect(trigger.getAttribute("aria-controls")).toBe(popup.id);
    const list = screen.getByRole("list", { name: "Child threads" });
    expect(list.getAttribute("data-child-thread-list")).toBe("header");
    fireEvent.click(
      screen.getByRole("button", { name: "Open child thread: Child B" }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "child-b",
      options: undefined,
    });
  });

  // The header variant draws a glyph rather than the sidebar's text slot, so
  // the accessible name is the only place its status is spelled out. It uses
  // the same vocabulary as a parent card, including a raised hand outranking
  // a reported runtime and an unknown kind saying nothing at all.
  it("labels header child rows with the shared status vocabulary", () => {
    renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({
              id: "monitor",
              title: "Monitor child",
              parentThreadId: "parent",
              indicator: "runtime",
              indicatorLabel: "Thread monitoring",
              createdAt: 101,
            }),
            thread({
              id: "asking",
              title: "Asking child",
              parentThreadId: "parent",
              hasPendingInteraction: true,
              indicator: "runtime",
              indicatorLabel: "Agent is working",
              createdAt: 102,
            }),
            thread({
              id: "future",
              title: "Future child",
              parentThreadId: "parent",
              indicator: "something-bb-ships-later" as never,
              indicatorLabel: "Brand new",
              createdAt: 103,
            }),
            thread({
              id: "idle",
              title: "Idle child",
              parentThreadId: "parent",
              createdAt: 104,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
      },
    );

    fireEvent.click(screen.getByRole("button", { name: "4 child threads" }));
    const list = screen.getByRole("list", { name: "Child threads" });
    expect(list.getAttribute("data-child-thread-list")).toBe("header");
    for (const name of [
      "Open child thread: Monitor child, Monitoring",
      "Open child thread: Asking child, Needs you",
      "Open child thread: Future child",
      "Open child thread: Idle child",
    ]) {
      expect(within(list).getByRole("button", { name })).toBeDefined();
    }
    // No text status slot in this variant, and no leftover raw host labels.
    expect(within(list).queryByText("Monitoring")).toBeNull();
    expect(within(list).queryByText("Needs you")).toBeNull();
    expect(within(list).queryByText("Brand new")).toBeNull();
  });

  it("keeps grandchildren collapsed until their child disclosure opens", () => {
    const rendered = renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({
              id: "child",
              title: "Child",
              parentThreadId: "parent",
              createdAt: 101,
            }),
            thread({
              id: "grandchild",
              title: "Grandchild",
              parentThreadId: "child",
              createdAt: 102,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
      },
    );

    fireEvent.click(screen.getByRole("button", { name: "1 child thread" }));
    expect(screen.queryByText("Grandchild")).toBeNull();

    const disclosure = screen.getByRole("button", {
      name: "Show 1 grandchild thread for Child",
    });
    expect(disclosure.getAttribute("aria-expanded")).toBe("false");
    fireEvent.click(disclosure);

    const grandchildList = screen.getByRole("list", {
      name: "Grandchildren of Child",
    });
    expect(grandchildList.getAttribute("data-grandchild-thread-list")).toBe(
      "header",
    );
    fireEvent.click(
      within(grandchildList).getByRole("button", {
        name: "Open grandchild thread: Grandchild",
      }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "grandchild",
      options: undefined,
    });
  });

  it("archives the selected child or grandchild from the header list", async () => {
    const rendered = renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({ id: "child", title: "Child", parentThreadId: "parent" }),
            thread({
              id: "grandchild",
              title: "Grandchild",
              parentThreadId: "child",
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
      },
    );

    fireEvent.click(screen.getByRole("button", { name: "1 child thread" }));
    fireEvent.contextMenu(
      screen.getByRole("button", { name: "Open child thread: Child" }),
    );
    fireEvent.click(
      within(await screen.findByRole("menu", { name: "Thread actions" })).getByText(
        "Archive",
      ),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "archive",
      threadId: "child",
    });

    fireEvent.click(
      screen.getByRole("button", {
        name: "Show 1 grandchild thread for Child",
      }),
    );
    fireEvent.contextMenu(
      screen.getByRole("button", {
        name: "Open grandchild thread: Grandchild",
      }),
    );
    fireEvent.click(
      within(await screen.findByRole("menu", { name: "Thread actions" })).getByText(
        "Archive",
      ),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "archive",
      threadId: "grandchild",
    });
    expect(rendered.sidebarActionCalls).not.toContainEqual({
      method: "archive",
      threadId: "parent",
    });
  });

  it("closes on Escape and restores focus to the trigger", () => {
    renderSlot(
      childrenChip,
      { threadId: "parent", projectId: "proj_1", isCompactViewport: false },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({
              id: "child",
              title: "Child",
              parentThreadId: "parent",
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
      },
    );

    const trigger = screen.getByRole("button", { name: "1 child thread" });
    fireEvent.click(trigger);
    expect(screen.getByRole("region", { name: "Child threads" })).toBeDefined();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("region", { name: "Child threads" })).toBeNull();
    expect(document.activeElement).toBe(trigger);
  });
});
