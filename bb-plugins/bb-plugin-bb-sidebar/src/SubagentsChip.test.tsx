// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, screen, within } from "@testing-library/react";
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
