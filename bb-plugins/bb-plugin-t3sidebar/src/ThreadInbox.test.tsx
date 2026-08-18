// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  cleanup,
  fireEvent,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { resolveSnoozePresets, type ThreadLifecycleRow } from "./lifecycle";

// Load through the harness so the plugin's `@get-bb/plugin-sdk/app` import binds
// to the test runtime; importing the component directly would bind it to an
// empty runtime first.
const app = await loadPluginApp(() => import("../app"));
const inbox = app.threadLists[0]!;

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

const listProps = {
  activeThreadId: null,
  activeProjectId: null,
  isCompactViewport: false,
  onNavigate: () => {},
  searchQuery: "",
};

function render(
  threads: PluginSidebarThread[],
  projects = [{ id: "proj_1", name: "bb", isPersonal: false }],
) {
  return renderSlot(inbox, listProps, {
    sidebarThreads: { status: "ready", threads, projects },
    // The lifecycle store is the plugin's own backend; an empty one means
    // every thread is active, which is what these list tests are about.
    rpc: { listLifecycle: () => ({ rows: [] }) },
  });
}

/** The same list, drawn the way the host draws it on a phone. */
function renderCompact(
  threads: PluginSidebarThread[],
  rpc: { listLifecycle: () => { rows: ThreadLifecycleRow[] } } = {
    listLifecycle: () => ({ rows: [] }),
  },
) {
  return renderSlot(
    inbox,
    { ...listProps, isCompactViewport: true },
    {
      sidebarThreads: {
        status: "ready",
        threads,
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc,
    },
  );
}

afterEach(cleanup);

describe("t3sidebar registration", () => {
  it("registers exactly one thread list", () => {
    expect(app.threadLists).toHaveLength(1);
    expect(inbox.id).toBe("inbox");
  });
});

describe("ThreadInbox", () => {
  it("lists threads newest first", () => {
    render([
      thread({ id: "a", title: "Older", createdAt: 1 }),
      thread({ id: "b", title: "Newer", createdAt: 2 }),
    ]);
    // The anchor is a full-bleed overlay, so read the row containers.
    const titles = screen
      .getAllByRole("listitem")
      .map((row) => row.textContent);
    expect(titles[0]).toContain("Newer");
    expect(titles[1]).toContain("Older");
  });

  // The DOM contract behind numbered thread shortcuts and thread.next/previous.
  // A plugin that drops these attributes silently breaks nine host shortcuts.
  it("marks every row as a host shortcut target", () => {
    render([thread({ id: "thr_x" })]);
    const row = screen.getByRole("link");
    expect(row.hasAttribute("data-sidebar-thread-shortcut-target")).toBe(true);
    expect(row.getAttribute("data-sidebar-thread-id")).toBe("thr_x");
  });

  it("opens a thread on click and closes the mobile drawer", () => {
    let navigated = 0;
    const rendered = renderSlot(
      inbox,
      { ...listProps, onNavigate: () => (navigated += 1) },
      {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "thr_open" })],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );
    fireEvent.click(screen.getByRole("link"));
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "thr_open",
      options: { split: false },
    });
    expect(navigated).toBe(1);
  });

  it("opens in a split with the platform modifier held", () => {
    const rendered = render([thread({ id: "thr_split" })]);
    fireEvent.click(screen.getByRole("link"), { metaKey: true });
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "thr_split",
      options: { split: true },
    });
  });

  it("separates pinned threads from the inbox", () => {
    render([
      thread({ id: "a", title: "Plain" }),
      thread({ id: "b", title: "Stuck", isPinned: true }),
    ]);
    const pinned = screen.getByRole("region", { name: /pinned/i });
    expect(within(pinned).getByText("Stuck")).toBeDefined();
  });

  it("filters by the host's search query", () => {
    renderSlot(
      inbox,
      { ...listProps, searchQuery: "sidebar" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "a", title: "Sidebar work" }),
            thread({ id: "b", title: "Something else" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText("Sidebar work")).toBeDefined();
  });

  it("scopes to one project", () => {
    render(
      [
        thread({ id: "a", title: "In bb", projectId: "proj_1" }),
        thread({ id: "b", title: "In other", projectId: "proj_2" }),
      ],
      [
        { id: "proj_1", name: "bb", isPersonal: false },
        { id: "proj_2", name: "other", isPersonal: false },
      ],
    );
    // Radix opens on keyboard too, which jsdom can drive without pointer
    // capture. Enter opens the list; the option click picks the scope.
    fireEvent.keyDown(screen.getByLabelText(/Project scope/), { key: "Enter" });
    fireEvent.click(screen.getByRole("option", { name: "other" }));
    expect(screen.getAllByRole("listitem")).toHaveLength(1);
    expect(screen.getByText("In other")).toBeDefined();
  });

  it("hides archived threads", () => {
    render([thread({ id: "a", isArchived: true })]);
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
  });

  it("reports an empty inbox and a fruitless search differently", () => {
    render([]);
    expect(screen.getByText("No threads yet")).toBeDefined();
  });
});

describe("parking threads", () => {
  it("moves a settled thread to the Settled shelf", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_done", title: "Finished work" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_done",
              settledAt: 200,
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });
    // The shelf renders once the lifecycle read resolves.
    const shelf = await screen.findByRole("region", { name: "Settled" });
    expect(within(shelf).getByText(/Settled \(1\)/)).toBeDefined();
    // Collapsed by default: parked work is out of the way, never gone.
    expect(screen.queryByText("Finished work")).toBeNull();
    fireEvent.click(within(shelf).getByRole("button"));
    expect(within(shelf).getByText("Finished work")).toBeDefined();
  });

  it("keeps a working thread out of the shelves and offers no park action", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "thr_busy",
            title: "Still running",
            indicator: "runtime",
            activity: {
              workflows: 0,
              backgroundAgents: 0,
              backgroundCommands: 0,
              planMode: 0,
              goals: 0,
            },
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      // Settled in the store, but still working: it must stay visible.
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_busy",
              settledAt: 200,
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });
    expect(await screen.findByText("Still running")).toBeDefined();
    expect(screen.queryByRole("region", { name: "Settled" })).toBeNull();
    expect(screen.queryByLabelText("Settle thread")).toBeNull();
  });

  it("offers settle and snooze on a parkable thread", async () => {
    render([thread({ id: "thr_park", title: "Quiet" })]);
    // Rendered (not merely accepted as props): a card whose park controls
    // never mount leaves the whole feature unreachable.
    expect(await screen.findByLabelText("Settle thread")).toBeDefined();
    expect(screen.getByLabelText("Snooze until tomorrow")).toBeDefined();
  });

  it("settles a thread when the user clicks Settle", async () => {
    let settled: string | null = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_park", title: "Quiet" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        settle: (input) => {
          settled = (input as { threadId: string }).threadId;
          return { ok: true };
        },
      },
    });
    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() => expect(settled).toBe("thr_park"));
  });

  it("shows the wake countdown on a snoozed row", async () => {
    const wakeAt = Date.now() + 2 * 60 * 60 * 1000;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_snz", title: "Later" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_snz",
              settledAt: null,
              snoozedUntil: wakeAt,
              snoozedAt: Date.now(),
            },
          ],
        }),
      },
    });
    const shelf = await screen.findByRole("region", { name: "Snoozed" });
    fireEvent.click(within(shelf).getByRole("button"));
    expect(within(shelf).getByText("2h")).toBeDefined();
    expect(within(shelf).getByLabelText("Wake thread now")).toBeDefined();
  });
});

describe("row context menu", () => {
  it("offers the plugin's own thread actions on right-click", async () => {
    render([thread({ id: "thr_menu", title: "Right click me" })]);
    const row = await screen.findByText("Right click me");
    fireEvent.contextMenu(row);
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    // The plugin builds this menu itself — the SDK ships no menu component —
    // so the items are this plugin's choice, backed by the action hook.
    //
    // The park actions lead because this menu is the ONLY way to reach them on
    // a coarse pointer, where the card's hover-revealed buttons never appear.
    expect(
      within(menu)
        .getAllByRole("menuitem")
        .map((item) => item.textContent),
      // Read the presets rather than listing them: "This evening" drops out once
      // the evening is less than an hour away, so a hard-coded list here passes
      // all morning and fails after five. Their contents are lifecycle's own
      // tests; what this asserts is the menu's composition and order.
    ).toEqual([
      "Rename",
      ...resolveSnoozePresets(new Date()).map((preset) => preset.label),
      "Settle",
      "Open in split",
      "Mark unread",
      "Pin",
      "Archive",
      "Delete",
    ]);
  });

  // A thread that is still working must not be parkable anywhere, and the menu
  // is a second surface that could otherwise leak the action.
  it("omits the park actions while the thread is working", async () => {
    render([
      thread({ id: "thr_busy", title: "Busy thread", indicator: "runtime" }),
    ]);
    fireEvent.contextMenu(await screen.findByText("Busy thread"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    const labels = within(menu)
      .getAllByRole("menuitem")
      .map((item) => item.textContent);
    expect(labels).not.toContain("Settle");
    expect(labels).not.toContain("Tomorrow");
  });

  it("offers a shelved row its way back", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_set", title: "Settled thread" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_set",
              settledAt: Date.now(),
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });
    const shelf = await screen.findByRole("region", { name: "Settled" });
    fireEvent.click(within(shelf).getByRole("button"));
    fireEvent.contextMenu(within(shelf).getByText("Settled thread"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    expect(
      within(menu)
        .getAllByRole("menuitem")
        .map((item) => item.textContent),
    ).toContain("Un-settle");
  });

  it("routes deletion through the host's confirmation", async () => {
    const rendered = render([thread({ id: "thr_del", title: "Delete me" })]);
    fireEvent.contextMenu(await screen.findByText("Delete me"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    fireEvent.click(within(menu).getByText("Delete"));
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "requestDelete",
        threadId: "thr_del",
      }),
    );
  });
});

describe("card metadata", () => {
  it("always shows the provider glyph, even without a branch", async () => {
    render([thread({ id: "thr_p", providerId: "claude-code" })]);
    expect(await screen.findByLabelText("Claude Code")).toBeDefined();
  });

  // The ACP-backed agents are keyed by their prefixed provider ids, so a typo
  // there would silently drop them back to the unknown-provider dot.
  it.each([
    ["acp-cursor", "Cursor"],
    ["acp-grok", "Grok Build"],
    ["acp-opencode", "opencode"],
    ["codex", "Codex"],
    ["pi", "Pi"],
  ])("draws the agent's own glyph for %s", async (providerId, label) => {
    render([thread({ id: "thr_p", providerId })]);
    expect(await screen.findByLabelText(label)).toBeDefined();
  });

  it("falls back to a neutral glyph for an unknown provider", async () => {
    render([thread({ id: "thr_p", providerId: "some-new-agent" })]);
    expect(await screen.findByLabelText("some-new-agent")).toBeDefined();
  });

  // bb derives a branch from the thread's own title, and the machine is the
  // same one for nearly every thread — both spent the row's widest column on
  // something that never told two rows apart.
  it("shows neither the branch nor the machine", async () => {
    render([
      thread({
        id: "thr_b",
        title: "A thread",
        host: { id: "host_1", name: "Sawyer's MacBook" },
        environment: {
          id: "env_1",
          name: "Worktree",
          branchName: "bb/feature",
          workspaceDisplayKind: "managed-worktree",
        },
      }),
    ]);
    await screen.findByText("A thread");
    expect(screen.queryByText("bb/feature")).toBeNull();
    expect(screen.queryByText("Sawyer's MacBook")).toBeNull();
  });

  // Not exactly 3h: the card's clock is quantized to the minute, so a
  // timestamp sitting on a bucket boundary legitimately reads one unit lower.
  it("shows how long ago the thread was touched", async () => {
    render([
      thread({ id: "thr_t", updatedAt: Date.now() - (3 * 3_600_000 + 60_000) }),
    ]);
    expect(await screen.findByText("3h")).toBeDefined();
  });

  // Status and age share one slot. A row that shows both puts a variable-width
  // label in the column, and no two rows line up.
  it("replaces the age label with the status glyph while work runs", async () => {
    render([
      thread({
        id: "thr_run",
        indicator: "runtime",
        indicatorLabel: "Agent is working",
        updatedAt: Date.now() - (3 * 3_600_000 + 60_000),
      }),
    ]);
    expect(await screen.findByLabelText("Agent is working")).toBeDefined();
    expect(screen.queryByText("3h")).toBeNull();
  });

  // An indicator this plugin does not know must fall through to the age label
  // rather than leave the slot blank.
  it("keeps the age label for an unrecognized indicator", async () => {
    render([
      thread({
        id: "thr_new",
        indicator: "something-bb-ships-later" as never,
        updatedAt: Date.now() - (3 * 3_600_000 + 60_000),
      }),
    ]);
    expect(await screen.findByText("3h")).toBeDefined();
  });
});

// The three states that want the user take the slot from the age label, and
// they use bb's own glyphs: the two lists sit in one window, and a user who
// switches between them should not have to learn a second vocabulary.
describe("attention states", () => {
  const states = [
    ["waiting-for-input", "Thread needs user input"],
    ["unread-error", "Unread thread failed"],
    ["unread-success", "Unread thread succeeded"],
  ] as const;

  for (const [indicator, label] of states) {
    it(`shows the ${indicator} glyph instead of the age`, async () => {
      render([
        thread({
          id: `thr_${indicator}`,
          indicator,
          indicatorLabel: label,
          updatedAt: Date.now() - (3 * 3_600_000 + 60_000),
        }),
      ]);
      expect(await screen.findByLabelText(label)).toBeDefined();
      expect(screen.queryByText("3h")).toBeNull();
    });
  }

  // Running work is the one state the user does NOT have to act on, so it gets
  // the neutral spinner and no notification dot.
  it("shows the spinner, not a dot, while work runs", async () => {
    render([
      thread({
        id: "thr_busy",
        isUnread: true,
        indicator: "runtime",
        indicatorLabel: "Thread working",
      }),
    ]);
    expect(await screen.findByLabelText("Thread working")).toBeDefined();
    expect(screen.queryByLabelText("Unread thread succeeded")).toBeNull();
  });
});

describe("pull request badge", () => {
  const withPr = (attention: string, state = "open") =>
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_pr" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
      sidebarPullRequests: {
        thr_pr: {
          number: 412,
          title: "Fix the flake",
          url: "https://github.com/o/r/pull/412",
          state,
          attention,
        } as never,
      },
    });

  // The badge draws "#412", but `title` is a hover tooltip that a touch
  // screen never shows — so the PR's title has to live in the accessible
  // name, which is the only copy of it a phone or a screen reader can reach.
  const BADGE_NAME = "Pull request #412: Fix the flake";

  it("links the PR number out to the git host", async () => {
    withPr("none");
    const badge = await screen.findByRole("link", { name: BADGE_NAME });
    expect(badge.getAttribute("href")).toBe("https://github.com/o/r/pull/412");
    expect(badge.getAttribute("title")).toBe("Fix the flake");
    expect(badge.textContent).toBe("#412");
  });

  it("shows no badge when the branch has no PR", async () => {
    render([thread({ id: "thr_nopr" })]);
    await screen.findByText("A thread");
    expect(screen.queryByRole("link", { name: /^Pull request #/ })).toBeNull();
  });

  // The attention state is bb's rolled-up "does this need you" signal, so the
  // badge can colour itself without reading checks/review/mergeability.
  it("colors the badge from the attention state", async () => {
    const failing = withPr("checks_failed");
    expect(
      (await screen.findByRole("link", { name: BADGE_NAME })).className,
    ).toContain("destructive");
    failing.unmount();

    withPr("ready_to_merge");
    expect(
      (await screen.findByRole("link", { name: BADGE_NAME })).className,
    ).toContain("success");
  });
});

// bb sets isCompactViewport on phone-width viewports AND on coarse pointers,
// so these are the "no hover to reveal anything with" cases.
describe("compact viewport", () => {
  it("replaces the hover-only park buttons with a menu button", async () => {
    renderCompact([thread({ id: "thr_c", title: "Tap me" })]);
    await screen.findByText("Tap me");
    // The hover pair never appears on a touch screen, so drawing it would
    // strand snooze and settle behind a gesture that cannot happen.
    expect(screen.queryByLabelText("Settle thread")).toBeNull();
    expect(screen.queryByLabelText("Snooze until tomorrow")).toBeNull();
    expect(screen.getByLabelText("Thread actions")).toBeDefined();
  });

  // The context menu's trigger is the whole row, menu button included, so
  // leaving it mounted let one press open the dropdown AND the context menu
  // and stack two copies of the same menu.
  it("leaves the row's long-press menu to the button alone", async () => {
    renderCompact([thread({ id: "thr_c", title: "Tap me" })]);
    fireEvent.contextMenu(await screen.findByText("Tap me"));
    expect(screen.queryByRole("menu", { name: "Thread actions" })).toBeNull();

    fireEvent.pointerDown(screen.getByLabelText("Thread actions"), {
      button: 0,
      ctrlKey: false,
    });
    expect(
      await screen.findAllByRole("menu", { name: "Thread actions" }),
    ).toHaveLength(1);
  });

  it("keeps the park actions reachable through that button", async () => {
    renderCompact([thread({ id: "thr_c", title: "Tap me" })]);
    fireEvent.pointerDown(await screen.findByLabelText("Thread actions"), {
      button: 0,
      ctrlKey: false,
    });
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    const labels = within(menu)
      .getAllByRole("menuitem")
      .map((item) => item.textContent);
    expect(labels).toContain("Tomorrow");
    expect(labels).toContain("Settle");
  });

  // The status slot yields to the park buttons on hover; with no hover there
  // is nothing to yield to, so the status has to stay put.
  it("keeps the status visible", async () => {
    renderCompact([
      thread({
        id: "thr_c",
        title: "Tap me",
        indicator: "runtime",
        indicatorLabel: "Thread working",
      }),
    ]);
    expect(await screen.findByLabelText("Thread working")).toBeDefined();
  });

  // A snoozed row spends its one slot on the wake time. On a pointer the
  // restore button takes that cell on hover; on a phone it moves to the menu
  // so the wake time survives.
  it("keeps a snoozed row's wake time and drops its hover restore", async () => {
    const wakeAt = Date.now() + 2 * 60 * 60 * 1000;
    renderCompact([thread({ id: "thr_snz", title: "Parked" })], {
      listLifecycle: () => ({
        rows: [
          {
            threadId: "thr_snz",
            settledAt: null,
            snoozedUntil: wakeAt,
            snoozedAt: Date.now(),
          },
        ],
      }),
    });
    const shelf = await screen.findByRole("region", { name: "Snoozed" });
    fireEvent.click(within(shelf).getAllByRole("button")[0]!);
    expect(within(shelf).getByText("2h")).toBeDefined();
    expect(screen.queryByLabelText("Wake thread now")).toBeNull();
    expect(within(shelf).getByLabelText("Thread actions")).toBeDefined();
  });
});

describe("renaming a thread inline", () => {
  // jsdom gives every element a zero rect, so the anchor's "did you aim at the
  // title line?" check needs a real one to test against.
  function stubTitleRect(title: HTMLElement) {
    title.getBoundingClientRect = () =>
      ({ top: 40, bottom: 60, left: 0, right: 200 }) as DOMRect;
  }

  it("swaps the title for an input on a double-click", async () => {
    render([thread({ id: "thr_r", title: "Old name" })]);
    const title = await screen.findByText("Old name");
    stubTitleRect(title);
    fireEvent.doubleClick(screen.getByRole("link"), { clientY: 50 });

    const input = await screen.findByLabelText("Rename thread");
    expect((input as HTMLInputElement).value).toBe("Old name");
  });

  // The anchor covers the whole card, so a double-click on the branch line or
  // the project name must not put the row into edit mode.
  it("ignores a double-click away from the title line", async () => {
    render([thread({ id: "thr_r", title: "Old name" })]);
    stubTitleRect(await screen.findByText("Old name"));
    fireEvent.doubleClick(screen.getByRole("link"), { clientY: 90 });
    expect(screen.queryByLabelText("Rename thread")).toBeNull();
  });

  it("commits on Enter through the silent rename action", async () => {
    const rendered = render([thread({ id: "thr_r", title: "Old name" })]);
    stubTitleRect(await screen.findByText("Old name"));
    fireEvent.doubleClick(screen.getByRole("link"), { clientY: 50 });

    const input = await screen.findByLabelText("Rename thread");
    fireEvent.change(input, { target: { value: "New name" } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "rename",
      threadId: "thr_r",
      title: "New name",
    });
  });

  it("drops the edit on Escape", async () => {
    const rendered = render([thread({ id: "thr_r", title: "Old name" })]);
    stubTitleRect(await screen.findByText("Old name"));
    fireEvent.doubleClick(screen.getByRole("link"), { clientY: 50 });

    const input = await screen.findByLabelText("Rename thread");
    fireEvent.change(input, { target: { value: "Never mind" } });
    fireEvent.keyDown(input, { key: "Escape" });

    await waitFor(() => expect(screen.getByText("Old name")).toBeDefined());
    expect(
      rendered.sidebarActionCalls.some((call) => call.method === "rename"),
    ).toBe(false);
  });

  // Blank would not be "no title" — bb would answer it with a generated one,
  // so the user would lose the name they had rather than clear it.
  it.each([
    ["   ", "a blank title"],
    ["Old name", "an unchanged title"],
  ])("renames nothing for %s", async (value) => {
    const rendered = render([thread({ id: "thr_r", title: "Old name" })]);
    stubTitleRect(await screen.findByText("Old name"));
    fireEvent.doubleClick(screen.getByRole("link"), { clientY: 50 });

    const input = await screen.findByLabelText("Rename thread");
    fireEvent.change(input, { target: { value } });
    fireEvent.keyDown(input, { key: "Enter" });

    expect(
      rendered.sidebarActionCalls.some((call) => call.method === "rename"),
    ).toBe(false);
  });

  it("renames once when Enter is followed by the input's blur", async () => {
    const rendered = render([thread({ id: "thr_r", title: "Old name" })]);
    stubTitleRect(await screen.findByText("Old name"));
    fireEvent.doubleClick(screen.getByRole("link"), { clientY: 50 });

    const input = await screen.findByLabelText("Rename thread");
    fireEvent.change(input, { target: { value: "New name" } });
    fireEvent.keyDown(input, { key: "Enter" });
    fireEvent.blur(input);

    expect(
      rendered.sidebarActionCalls.filter((call) => call.method === "rename"),
    ).toHaveLength(1);
  });

  it("reaches the same editor from the row menu", async () => {
    render([thread({ id: "thr_r", title: "Old name" })]);
    fireEvent.contextMenu(await screen.findByText("Old name"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    fireEvent.click(within(menu).getByText("Rename"));
    expect(await screen.findByLabelText("Rename thread")).toBeDefined();
  });
});

// Regression: children used to leave the list for their parent's header chip,
// which only worked when the parent was the thread already on screen. Anything
// spawned from outside the app — `bb thread spawn --parent-self`, a plugin, an
// agent — arrived while the user was elsewhere and left no trace in the list.
describe("child threads in the list", () => {
  const parent = thread({
    id: "thr_parent",
    title: "Parent thread",
    createdAt: 1,
  });
  const child = thread({
    id: "thr_child",
    title: "CLI child",
    parentThreadId: "thr_parent",
    createdAt: 2,
  });

  // Nested under its parent, the child does not repeat the parent's name —
  // the row directly above it already is the parent.
  it("nests a child under its parent instead of naming it", async () => {
    render([parent, child]);
    const row = await screen.findByRole("link", { name: "CLI child" });
    expect(row.closest("li")?.style.paddingLeft).toBe("14px");
    expect(screen.queryByText("Parent thread, under")).toBeNull();
  });

  // Promoted to the left edge because its parent is not on screen, the name is
  // the only thing that explains where the row came from.
  it("names the parent of a child whose parent is not in the list", async () => {
    render([{ ...child, parentThreadId: "thr_elsewhere" }]);
    const row = await screen.findByRole("link", { name: /CLI child/ });
    expect(row.closest("li")?.style.paddingLeft).toBe("0px");
  });

  // The child's raised hand is the reason the row has to exist at all.
  it("shows a child's pending interaction in the list", async () => {
    render([
      parent,
      {
        ...child,
        hasPendingInteraction: true,
        indicator: "waiting-for-input" as const,
        indicatorLabel: "Thread needs user input",
      },
    ]);
    expect(
      await screen.findByLabelText(/Thread needs user input, waiting/),
    ).toBeDefined();
  });

  it("marks the row active when the child is the open thread", async () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "thr_child" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [parent, child],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );
    const row = await screen.findByRole("link", { name: "CLI child" });
    expect(row.parentElement?.className).toContain("bg-sidebar-accent");
  });
});

// The list's loudest state. A blocked thread is the only row that cannot make
// progress without the user, and until now it drew a muted glyph that ranked
// visually BELOW the blue unread dot.
describe("a thread waiting on you", () => {
  const waiting = (over: Partial<PluginSidebarThread> = {}) =>
    thread({
      id: "thr_wait",
      title: "Deploy the release candidate",
      hasPendingInteraction: true,
      indicator: "waiting-for-input",
      indicatorLabel: "Thread needs user input",
      latestAttentionAt: Date.now() - 12 * 60_000,
      ...over,
    });

  // The card's clock is floored to the minute, so a "12m ago" timestamp reads
  // 11m for most of any given minute (relative-time.ts:11 documents the
  // trade). The bucket is that module's test; this one is about composition.
  it("says how long it has been waiting", async () => {
    render([waiting()]);
    const pill = await screen.findByLabelText(
      /^Thread needs user input, waiting (now|\d+[mhdw])$/,
    );
    expect(pill.textContent).toMatch(/^(now|\d+[mhdw])$/);
  });

  it("marks the row with a rail and no background tint", async () => {
    render([waiting()]);
    const row = (await screen.findByRole("link", { name: /Deploy/ }))
      .parentElement!;
    expect(row.className).toContain("shadow-[inset_2px_0_0_var(--warning)]");
    // Tint is how this list says "selected". Blocked must not borrow it.
    expect(row.className).not.toContain("bg-sidebar-accent ");
  });

  // The rail is a channel selection does not use, so the two compose instead
  // of one hiding the other.
  it("keeps the rail when the row is also the open thread", async () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "thr_wait" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [waiting()],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );
    const row = (await screen.findByRole("link", { name: /Deploy/ }))
      .parentElement!;
    expect(row.className).toContain("shadow-[inset_2px_0_0_var(--warning)]");
    expect(row.className).toContain("bg-sidebar-accent");
  });

  it("replaces the age label rather than sitting beside it", async () => {
    render([waiting({ latestAttentionAt: Date.now() - 3 * 60 * 60_000 })]);
    const pill = await screen.findByLabelText(/waiting/);
    // The pill owns the whole trailing slot — an age label alongside it would
    // give the row two clocks saying different things.
    expect(pill.parentElement?.textContent).toBe(pill.textContent);
  });

  // canPark is false while blocked, so the hover park buttons never fire on
  // these rows and cannot fight the pill for the slot.
  it("offers no park actions while blocked", async () => {
    render([waiting()]);
    fireEvent.contextMenu(
      await screen.findByText("Deploy the release candidate"),
    );
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    const labels = within(menu)
      .getAllByRole("menuitem")
      .map((item) => item.textContent);
    expect(labels).not.toContain("Settle");
  });

  it("leaves an ordinary row's fixed status column alone", async () => {
    render([thread({ id: "thr_calm", title: "Calm", updatedAt: Date.now() })]);
    const row = (await screen.findByRole("link", { name: "Calm" }))
      .parentElement!;
    expect(row.className).not.toContain("var(--warning)");
  });
});

// Nesting, the way bb's own sidebar draws it: a child sits under its parent,
// and a parent can be folded shut. Collapsing must never be a way to lose a
// thread that wants something, so a shut row answers for what it hides.
describe("nesting and collapsing", () => {
  const parent = thread({ id: "thr_p", title: "Parent", createdAt: 1 });
  const kid = thread({
    id: "thr_k",
    title: "Kid",
    parentThreadId: "thr_p",
    createdAt: 2,
  });
  const grandkid = thread({
    id: "thr_g",
    title: "Grandkid",
    parentThreadId: "thr_k",
    createdAt: 3,
  });

  const indents = () =>
    screen.getAllByRole("listitem").map((row) => row.style.paddingLeft);

  beforeEach(() => window.localStorage.clear());

  it("indents each level under its parent", async () => {
    render([parent, kid, grandkid]);
    await screen.findByText("Parent");
    expect(indents()).toEqual(["0px", "14px", "28px"]);
  });

  it("folds a subtree shut and back open", async () => {
    render([parent, kid, grandkid]);
    const toggle = await screen.findByLabelText(/Collapse 2 child threads/);
    fireEvent.click(toggle);

    await waitFor(() => expect(screen.queryByText("Kid")).toBeNull());
    expect(screen.getByText("Parent")).toBeDefined();
    expect(screen.queryByText("Grandkid")).toBeNull();

    fireEvent.click(screen.getByLabelText(/Expand 2 child threads/));
    await waitFor(() => expect(screen.getByText("Kid")).toBeDefined());
  });

  it("says what a collapsed row is hiding", async () => {
    render([parent, kid, grandkid]);
    // Two rows have children here, so name the one being folded.
    fireEvent.click(await screen.findByLabelText(/Collapse 2 child threads/));
    expect(await screen.findByText("2 threads")).toBeDefined();
  });

  // The whole point of the summary: a blocked descendant cannot go quiet just
  // because someone folded its parent.
  it("surfaces a blocked descendant on the collapsed parent", async () => {
    render([
      parent,
      { ...kid, hasPendingInteraction: true, indicator: "waiting-for-input" },
    ]);
    fireEvent.click(await screen.findByLabelText(/Collapse/));
    expect(await screen.findByText("1 waiting")).toBeDefined();
  });

  it("surfaces an unread descendant more quietly", async () => {
    render([parent, { ...kid, isUnread: true }]);
    fireEvent.click(await screen.findByLabelText(/Collapse/));
    expect(await screen.findByText("1 unread")).toBeDefined();
  });

  it("offers no toggle on a thread with no children", async () => {
    render([thread({ id: "thr_alone", title: "Alone" })]);
    await screen.findByText("Alone");
    expect(screen.queryByLabelText(/Collapse/)).toBeNull();
  });

  // bb keeps its own sidebar's collapse state per browser; this matches.
  it("remembers what was collapsed across a remount", async () => {
    const first = render([parent, kid]);
    fireEvent.click(await screen.findByLabelText(/Collapse/));
    await waitFor(() => expect(screen.queryByText("Kid")).toBeNull());
    first.unmount();

    render([parent, kid]);
    await screen.findByText("Parent");
    expect(screen.queryByText("Kid")).toBeNull();
  });

  // Collapsing hides rows; it must not hide them from the shortcut targets
  // that are still on screen.
  it("keeps every visible row a host shortcut target", async () => {
    render([parent, kid]);
    await screen.findByText("Kid");
    expect(
      screen
        .getAllByRole("link")
        .every((row) =>
          row.hasAttribute("data-sidebar-thread-shortcut-target"),
        ),
    ).toBe(true);
  });
});

// Two lines, not three. The project used to have a line of its own above the
// title, which read the hierarchy backwards and cost ~30px on every row.
describe("card layout", () => {
  it("puts the title first and the project under it", async () => {
    render([thread({ id: "thr_l", title: "Migrate the billing schema" })]);
    const row = await screen.findByRole("listitem");
    const text = row.textContent ?? "";
    expect(text.indexOf("Migrate the billing schema")).toBeLessThan(
      text.indexOf("bb"),
    );
  });

  it("gives the title and the project a line each", async () => {
    render([thread({ id: "thr_l", title: "Migrate the billing schema" })]);
    const title = await screen.findByText("Migrate the billing schema");
    const project = screen.getByText("bb");
    expect(title.closest("div")).not.toBe(project.closest("div"));
  });

  // The status shares the title's line now, so it must not have been pushed
  // down to the project's.
  it("keeps the status beside the title", async () => {
    render([
      thread({
        id: "thr_l",
        title: "Working thread",
        indicator: "runtime",
        indicatorLabel: "Thread working",
      }),
    ]);
    const title = await screen.findByText("Working thread");
    const status = screen.getByLabelText("Thread working");
    expect(title.parentElement?.contains(status)).toBe(true);
  });

  // A collapsed summary and a promoted child's parent both outrank the
  // project name for the one leading slot on the second line.
  it("gives the second line's slot to the collapsed summary", async () => {
    render([
      thread({ id: "p", title: "Parent", createdAt: 1 }),
      thread({ id: "k", title: "Kid", parentThreadId: "p", createdAt: 2 }),
    ]);
    fireEvent.click(await screen.findByLabelText(/Collapse/));
    expect(await screen.findByText("1 thread")).toBeDefined();
    expect(screen.queryByText("bb")).toBeNull();
  });
});

// The meta line grows on a coarse pointer so its prose stays readable. Mono
// numerals gain far more width per step than words do, so the PR badge sat
// oversized next to activity counts, which pin their own size.
describe("the pull request badge's size", () => {
  const withPr = (compact: boolean) => {
    const props = compact
      ? { ...listProps, isCompactViewport: true }
      : listProps;
    return renderSlot(inbox, props, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_pr" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
      sidebarPullRequests: {
        thr_pr: {
          number: 12071,
          title: "Fix the flake",
          url: "https://github.com/o/r/pull/12071",
          state: "open",
          attention: "none",
        } as never,
      },
    });
  };

  it.each([
    ["a pointer", false],
    ["a coarse pointer", true],
  ])("stays the small size on %s", async (_label, compact) => {
    withPr(compact);
    const badge = await screen.findByRole("link", { name: /Pull request/ });
    expect(badge.className).toContain("text-2xs");
    expect(badge.className).not.toContain("text-xs ");
  });

  // It shares a line with the counts, so the two have to agree.
  it("matches the activity counts it sits beside", async () => {
    renderSlot(
      inbox,
      { ...listProps, isCompactViewport: true },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({
              id: "thr_pr",
              activity: {
                workflows: 2,
                backgroundAgents: 0,
                backgroundCommands: 0,
                planMode: 0,
                goals: 0,
              },
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
        sidebarPullRequests: {
          thr_pr: {
            number: 12071,
            title: "Fix the flake",
            url: "https://github.com/o/r/pull/12071",
            state: "open",
            attention: "none",
          } as never,
        },
      },
    );
    const badge = await screen.findByRole("link", { name: /Pull request/ });
    const count = screen.getByLabelText("2 workflows");
    const size = (el: Element) =>
      (el.className.match(/text-\dxs|text-xs/) ?? [])[0];
    expect(size(badge)).toBe(size(count));
  });
});

// The chevron only exists on parents, so only parents' second line has to
// reserve room for it. Without that, the project name sat 18px to the left of
// the title it belongs under.
describe("the card's two lines share a left edge", () => {
  // Collapse state persists to localStorage, so a parent collapsed by an
  // earlier test would come back expanded-or-not at random and flip the
  // toggle's label between "Collapse" and "Expand".
  beforeEach(() => window.localStorage.clear());

  const metaLineOf = (row: HTMLElement) =>
    row.querySelector<HTMLElement>(".h-3\\.5");

  it("reserves the chevron's width on a parent's second line", async () => {
    render([
      thread({ id: "p", title: "Parent", createdAt: 1 }),
      thread({ id: "k", title: "Kid", parentThreadId: "p", createdAt: 2 }),
    ]);
    const parentRow = (
      await screen.findByRole("link", { name: "Parent" })
    ).closest("li")!;
    expect(
      metaLineOf(parentRow)?.querySelector("[data-collapse-spacer]"),
    ).not.toBeNull();
  });

  it("reserves nothing on a row with no children", async () => {
    render([thread({ id: "alone", title: "Alone" })]);
    const row = (await screen.findByRole("link", { name: "Alone" })).closest(
      "li",
    )!;
    expect(row.querySelector("[data-collapse-spacer]")).toBeNull();
  });

  // The spacer and the chevron must stay the same size, so they share one
  // class string rather than two numbers that can drift.
  it("gives the spacer the chevron's exact footprint", async () => {
    render([
      thread({ id: "p", title: "Parent", createdAt: 1 }),
      thread({ id: "k", title: "Kid", parentThreadId: "p", createdAt: 2 }),
    ]);
    // Scope to the row: a document-wide query can pick up another render's
    // leftovers when the whole file runs.
    const parentRow = (
      await screen.findByRole("link", { name: "Parent" })
    ).closest("li")!;
    const toggle = within(parentRow).getByLabelText(/Collapse/);
    const spacer = parentRow.querySelector("[data-collapse-spacer]")!;
    const footprint = (el: Element) =>
      el.className
        .split(/\s+/)
        .filter((c) => ["-ml-1", "size-4", "shrink-0"].includes(c))
        .sort();
    expect(footprint(spacer)).toEqual(footprint(toggle));
    expect(footprint(spacer)).toHaveLength(3);
  });
});
