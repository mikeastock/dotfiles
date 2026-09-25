// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cleanup,
  fireEvent,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import type { ChannelsSnapshot, SidebarChannel } from "./channels";

const toastMocks = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
  message: vi.fn(),
  dismiss: vi.fn(),
}));
vi.mock("sonner", () => ({ toast: toastMocks }));

// Load through the harness so `@get-bb/plugin-sdk/app` binds to the test
// runtime.
const app = await loadPluginApp(() => import("../app"));
const inbox = app.threadLists[0]!;

const listProps = {
  activeThreadId: null,
  activeProjectId: null,
  isCompactViewport: false,
  onNavigate: () => {},
  searchQuery: "",
  // Required by the pinned SDK's types; bb 0.43 no longer passes it and this
  // sidebar never renders it.
  Original: () => null,
};

const SHELF_EXPANSION_STORAGE_KEY = "bb-sidebar:shelf-expansion:v1";

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  window.history.replaceState(null, "", "/");
  toastMocks.error.mockReset();
});

function thread(overrides: Partial<PluginSidebarThread> = {}): PluginSidebarThread {
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

function channel(overrides: Partial<SidebarChannel> = {}): SidebarChannel {
  return {
    id: "room_1",
    name: "bedrock",
    pinned: false,
    unread: false,
    working: false,
    needsYouCount: 0,
    updatedAt: 100,
    ...overrides,
  };
}

function render(
  snapshot: ChannelsSnapshot | (() => never),
  extraRpc: Record<string, (input: unknown) => unknown> = {},
) {
  return renderSlot(inbox, listProps, {
    sidebarThreads: {
      status: "ready",
      threads: [thread({ title: "A thread" })],
      projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
    },
    rpc: {
      listLifecycle: () => ({ rows: [] }),
      listChannels: typeof snapshot === "function" ? snapshot : () => snapshot,
      ...extraRpc,
    },
  });
}

describe("Channels shelf", () => {
  it("lists Bot Teams channels as links to their pages", async () => {
    render({
      available: true,
      channels: [
        channel({ id: "room_1", name: "bedrock", pinned: true }),
        channel({ id: "room_2", name: "ops" }),
      ],
    });

    const shelf = await screen.findByRole("region", { name: "Channels" });
    const bedrock = within(shelf).getByRole("link", { name: "bedrock" });
    expect(bedrock.getAttribute("href")).toBe("/plugins/bot-teams/channels/room_1");
    expect(
      within(shelf).getByRole("link", { name: "ops" }).getAttribute("href"),
    ).toBe("/plugins/bot-teams/channels/room_2");
    // Threads still render beneath it.
    expect(screen.getByRole("link", { name: /A thread/ })).toBeDefined();
  });

  it("shows no shelf when Bot Teams is unavailable", async () => {
    const rendered = render({ available: false, reason: "not installed" });

    await waitFor(() =>
      expect(rendered.rpcCalls.some((call) => call.method === "listChannels")).toBe(true),
    );
    expect(screen.queryByRole("region", { name: "Channels" })).toBeNull();
    expect(screen.getByRole("link", { name: /A thread/ })).toBeDefined();
  });

  it("shows no shelf when the channel read fails outright", async () => {
    const rendered = render(() => {
      throw new Error("backend reloading");
    });

    await waitFor(() =>
      expect(rendered.rpcCalls.some((call) => call.method === "listChannels")).toBe(true),
    );
    expect(screen.queryByRole("region", { name: "Channels" })).toBeNull();
    expect(screen.getByRole("link", { name: /A thread/ })).toBeDefined();
  });

  it("shows no shelf when Bot Teams has no open channels", async () => {
    const rendered = render({ available: true, channels: [] });

    await waitFor(() =>
      expect(rendered.rpcCalls.some((call) => call.method === "listChannels")).toBe(true),
    );
    expect(screen.queryByRole("region", { name: "Channels" })).toBeNull();
  });

  it("labels channels that need you, are working, or are unread", async () => {
    render({
      available: true,
      channels: [
        channel({ id: "a", name: "needs", needsYouCount: 2 }),
        channel({ id: "b", name: "busy", working: true }),
        channel({ id: "c", name: "fresh", unread: true }),
      ],
    });

    expect(
      await screen.findByRole("link", { name: "needs (2 requests need you)" }),
    ).toBeDefined();
    expect(screen.getByRole("link", { name: "busy (Working)" })).toBeDefined();
    expect(screen.getByRole("link", { name: "fresh (Unread)" })).toBeDefined();
  });

  it("marks the open channel current and does not call it unread", async () => {
    window.history.replaceState(null, "", "/plugins/bot-teams/channels/room_1");
    render({
      available: true,
      channels: [channel({ id: "room_1", name: "bedrock", unread: true })],
    });

    const link = await screen.findByRole("link", { name: "bedrock" });
    expect(link.getAttribute("aria-current")).toBe("page");
  });

  it("collapsed, keeps the open channel and channels that need you", async () => {
    window.localStorage.setItem(
      SHELF_EXPANSION_STORAGE_KEY,
      JSON.stringify({ channels: false }),
    );
    window.history.replaceState(null, "", "/plugins/bot-teams/channels/open");
    render({
      available: true,
      channels: [
        channel({ id: "open", name: "open-one" }),
        channel({ id: "asks", name: "asks", needsYouCount: 1 }),
        channel({ id: "quiet", name: "quiet" }),
      ],
    });

    const toggle = await screen.findByRole("button", { name: /Channels \(3\)/ });
    expect(toggle.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByRole("link", { name: "open-one" })).toBeDefined();
    expect(
      screen.getByRole("link", { name: "asks (1 request needs you)" }),
    ).toBeDefined();
    expect(screen.queryByRole("link", { name: "quiet" })).toBeNull();

    fireEvent.click(toggle);
    expect(await screen.findByRole("link", { name: "quiet" })).toBeDefined();
  });

  it("marks an unread channel read when it is opened", async () => {
    const rendered = render(
      {
        available: true,
        channels: [channel({ id: "room_1", name: "bedrock", unread: true, updatedAt: 500 })],
      },
      { setChannelState: () => ({ ok: true }) },
    );

    fireEvent.click(await screen.findByRole("link", { name: "bedrock (Unread)" }));

    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "setChannelState",
        input: { id: "room_1", lastReadAt: 500 },
      }),
    );
  });

  it("does not write when a read channel is opened", async () => {
    const rendered = render(
      { available: true, channels: [channel({ name: "bedrock" })] },
      { setChannelState: () => ({ ok: true }) },
    );

    fireEvent.click(await screen.findByRole("link", { name: "bedrock" }));

    expect(rendered.rpcCalls.some((call) => call.method === "setChannelState")).toBe(false);
  });

  it("pins, marks unread, and archives from the context menu", async () => {
    const rendered = render(
      { available: true, channels: [channel({ id: "room_1", name: "bedrock" })] },
      { setChannelState: () => ({ ok: true }) },
    );

    for (const [label, input] of [
      ["Pin", { id: "room_1", pinned: true }],
      ["Mark as unread", { id: "room_1", markUnread: true }],
      ["Archive channel", { id: "room_1", archived: true }],
    ] as const) {
      fireEvent.contextMenu(await screen.findByRole("link", { name: "bedrock" }));
      fireEvent.click(
        within(await screen.findByRole("menu", { name: "bedrock actions" })).getByText(label),
      );
      await waitFor(() =>
        expect(rendered.rpcCalls).toContainEqual({ method: "setChannelState", input }),
      );
    }
  });

  it("offers unpin and mark-as-read for a pinned unread channel", async () => {
    const rendered = render(
      {
        available: true,
        channels: [channel({ id: "room_1", name: "bedrock", pinned: true, unread: true, updatedAt: 42 })],
      },
      { setChannelState: () => ({ ok: true }) },
    );

    fireEvent.contextMenu(await screen.findByRole("link", { name: "bedrock (Unread)" }));
    const menu = await screen.findByRole("menu", { name: "bedrock actions" });
    expect(within(menu).queryByText("Pin")).toBeNull();
    fireEvent.click(within(menu).getByText("Mark as read"));
    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "setChannelState",
        input: { id: "room_1", lastReadAt: 42 },
      }),
    );

    fireEvent.contextMenu(screen.getByRole("link", { name: "bedrock (Unread)" }));
    fireEvent.click(
      within(await screen.findByRole("menu", { name: "bedrock actions" })).getByText("Unpin"),
    );
    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "setChannelState",
        input: { id: "room_1", pinned: false },
      }),
    );
  });

  it("tells the user when a channel write fails", async () => {
    render(
      { available: true, channels: [channel({ name: "bedrock" })] },
      {
        setChannelState: () => {
          throw new Error("Channel not found");
        },
      },
    );

    fireEvent.contextMenu(await screen.findByRole("link", { name: "bedrock" }));
    fireEvent.click(
      within(await screen.findByRole("menu", { name: "bedrock actions" })).getByText(
        "Archive channel",
      ),
    );

    await waitFor(() =>
      expect(toastMocks.error).toHaveBeenCalledWith(
        "Could not archive channel",
        expect.objectContaining({ description: expect.stringContaining("Channel not found") }),
      ),
    );
  });

  it("re-reads channels after a write", async () => {
    const rendered = render(
      { available: true, channels: [channel({ name: "bedrock" })] },
      { setChannelState: () => ({ ok: true }) },
    );
    await screen.findByRole("link", { name: "bedrock" });
    const readsBefore = rendered.rpcCalls.filter((call) => call.method === "listChannels").length;

    fireEvent.contextMenu(screen.getByRole("link", { name: "bedrock" }));
    fireEvent.click(
      within(await screen.findByRole("menu", { name: "bedrock actions" })).getByText("Pin"),
    );

    await waitFor(() =>
      expect(
        rendered.rpcCalls.filter((call) => call.method === "listChannels").length,
      ).toBeGreaterThan(readsBefore),
    );
  });
});
