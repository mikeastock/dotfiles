// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  act,
  cleanup,
  fireEvent,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { loadPluginApp, renderSlot } from "@get-bb/plugin-sdk/testing/app";
import type { PluginSidebarThread } from "@get-bb/plugin-sdk";
import { DEFAULT_SNOOZE_PRESET_CONFIG, formatSnoozeWakeTime } from "./lifecycle";
import type { SidebarProvider } from "./ProviderGlyph";

const toastMocks = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
  message: vi.fn(),
  dismiss: vi.fn(),
}));

vi.mock("sonner", () => ({ toast: toastMocks }));

Object.defineProperty(Element.prototype, "scrollIntoView", {
  configurable: true,
  value: vi.fn(),
});
Object.defineProperty(Document.prototype, "elementFromPoint", {
  configurable: true,
  value: vi.fn(),
});

// Load through the harness so the plugin's `@get-bb/plugin-sdk/app` import binds
// to the test runtime; importing the component directly would bind it to an
// empty runtime first.
const app = await loadPluginApp(() => import("../app"));
const inbox = app.threadLists[0]!;
const sidebarSettings = app.settingsSections[0]!;

/** A settle that found no runtime loaded and no terminals to report. */
const SETTLED_NOTHING = {
  closedTerminals: 0,
  keptTerminals: 0,
  stoppedRuntime: false,
};

const defaultSidebarSettings = {
  snoozePresets: "30m, 2h, 1d, 1w",
  inactiveThreadsEnabled: true,
  inactiveAfterHours: 6,
  showRunningChildrenWhenCollapsed: true,
  autoSettleInactive: true,
  autoSettleAfterDays: 3,
  autoSettleOnMerge: true,
};

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

function provider(
  id: string,
  displayName: string,
  logoUrl: string | null,
): SidebarProvider {
  return {
    id,
    pluginId: `provider-${id}`,
    displayName,
    available: true,
    maintenance: {
      health: true,
      usage: false,
      installation: true,
    },
    logoUrl,
    capabilities: {
      modelCatalogScope: "workspace",
      permissionModes: ["full"],
      supportsFork: true,
      supportsNativeUserQuestion: false,
      supportsServiceTier: false,
      supportsSessionRewind: true,
      supportsThreadArchive: false,
      supportsThreadRename: false,
    },
    composerActions: [],
  };
}

const defaultProviders = [
  provider("codex", "Codex", "/api/v1/system/providers/codex/logo"),
  provider(
    "claude-code",
    "Claude Code",
    "/api/v1/system/providers/claude-code/logo",
  ),
];

const listProps = {
  activeThreadId: null,
  activeProjectId: null,
  isCompactViewport: false,
  onNavigate: () => {},
  searchQuery: "",
  Original: () => null,
};

it("shows direct subthreads in the hover card and opens them by keyboard or click", async () => {
  const rendered = render([
    thread({ id: "parent", title: "Parent work" }),
    thread({ id: "b", parentThreadId: "parent", title: "Review", createdAt: 20, providerId: "claude-code", hasPendingInteraction: true }),
    thread({ id: "a", parentThreadId: "parent", title: null, titleFallback: "Implementation", createdAt: 10, indicator: "runtime", indicatorLabel: "Working" }),
    thread({ id: "archived", parentThreadId: "parent", title: "Archived work", isArchived: true }),
    thread({ id: "grandchild", parentThreadId: "a", title: "Nested work" }),
  ]);
  const row = screen.getByRole("link", { name: "Parent work" });
  act(() => row.focus());
  const details = await screen.findByRole("dialog", { name: "Thread details" });
  const toggle = within(details).getByRole("button", { name: "Subthreads (2)", expanded: false });
  expect(within(details).queryByRole("list", { name: "Subthreads" })).toBeNull();
  fireEvent.click(toggle);
  expect(toggle.getAttribute("aria-expanded")).toBe("true");
  const list = within(details).getByRole("list", { name: "Subthreads" });
  const items = within(list).getAllByRole("button");
  expect(items.map((item) => item.getAttribute("aria-label"))).toEqual([
    "Open subthread: Implementation", "Open subthread: Review",
  ]);
  expect(list.textContent).toContain("Codex · Working");
  expect(list.textContent).toContain("Claude Code · Needs you");
  expect(within(details).queryByText("Archived work")).toBeNull();
  expect(within(details).queryByText("Nested work")).toBeNull();
  fireEvent.keyDown(row, { key: "Tab" });
  expect(document.activeElement).toBe(toggle);
  fireEvent.click(toggle);
  expect(within(details).queryByRole("list", { name: "Subthreads" })).toBeNull();
  fireEvent.click(toggle);
  fireEvent.keyDown(toggle, { key: "Tab", shiftKey: true });
  await waitFor(() => expect(document.activeElement).toBe(row));
  fireEvent.pointerMove(row, { pointerType: "mouse" });
  const reopened = await screen.findByRole("dialog", { name: "Thread details" });
  fireEvent.click(within(reopened).getByRole("button", { name: "Subthreads (2)", expanded: false }));
  fireEvent.click(within(reopened).getByRole("button", { name: "Open subthread: Review" }));
  expect(rendered.sidebarActionCalls).toContainEqual({ method: "open", threadId: "b" });
  expect(screen.queryByRole("dialog", { name: "Thread details" })).toBeNull();
});

it("shows port details in the thread hover card", async () => {
  localStorage.setItem("bb-sidebar:port-link-host:v1", "host_local");
  const openUrl = vi.fn(() => true);
  renderSlot(inbox, listProps, {
    openUrl,
    sidebarThreads: {
      status: "ready",
      threads: [thread({ title: "Port details", host: { id: "host_local", name: "Local" }, environment: {
        id: "env_ports", name: null, branchName: "main", workspaceDisplayKind: "other",
      } })],
      projects: [],
    },
    rpc: {
      listLifecycle: () => ({ rows: [] }),
      getOpenPorts: () => ({ groups: [{ environmentId: "env_ports", ports: [
        { port: 3000, processName: "node", pid: 1234, address: "127.0.0.1", source: "process" },
        { port: 5432, service: "postgres", container: "app-db-1", address: "0.0.0.0", source: "docker" },
      ] }] }),
      getThreadExecutionDetails: () => null,
    },
  });
  fireEvent.pointerMove(screen.getByRole("link", { name: "Port details" }), { pointerType: "mouse" });
  const details = await screen.findByRole("dialog", { name: "Thread details" });
  expect(details.textContent).toContain("Workspace ports (2)");
  expect(details.textContent).toContain(":3000 node");
  expect(details.textContent).toContain("127.0.0.1 · PID 1234");
  expect(details.textContent).toContain(":5432 postgres");
  expect(details.textContent).toContain("Docker · app-db-1");
  expect(screen.queryByRole("img", { name: "Open ports started by this thread" })).toBeNull();
  const portLink = screen.getAllByRole("link", { name: "Open port 3000" })[0]!;
  expect(portLink.getAttribute("href")).toBe("http://127.0.0.1:3000/");
  fireEvent.click(portLink);
  expect(openUrl).toHaveBeenCalledWith("http://127.0.0.1:3000/");
  const row = screen.getByRole("link", { name: "Port details" });
  act(() => row.focus());
  fireEvent.keyDown(row, { key: "Tab" });
  expect(document.activeElement).toBe(portLink);
  fireEvent.keyDown(portLink, { key: "Escape" });
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Thread details" })).toBeNull());
  expect(document.activeElement).toBe(row);

});

it("keeps a long workspace port list accessible even without local links", async () => {
  renderSlot(inbox, listProps, {
    sidebarThreads: { status: "ready", projects: [], threads: [thread({ title: "Many ports", environment: {
      id: "env_ports", name: null, branchName: "main", workspaceDisplayKind: "other",
    } })] },
    rpc: {
      listLifecycle: () => ({ rows: [] }), getThreadExecutionDetails: () => null,
      getOpenPorts: () => ({ groups: [{ environmentId: "env_ports", ports: Array.from({ length: 20 }, (_, i) => ({ port: 8000 + i })) }] }),
    },
  });
  const row = screen.getByRole("link", { name: "Many ports" });
  act(() => row.focus());
  const list = await screen.findByRole("region", { name: "Workspace port list" });
  expect(within(list).getByText(":8019")).toBeDefined();
  fireEvent.keyDown(row, { key: "Tab" });
  expect(document.activeElement).toBe(list);
  fireEvent.keyDown(list, { key: "Tab", shiftKey: true });
  await waitFor(() => expect(document.activeElement).toBe(row));
});

it("marks only the owning thread without a count and clears its icon when the port closes", async () => {
  const environment = { id: "env_ports", name: null, branchName: "main", workspaceDisplayKind: "other" as const };
  let groups = [{ environmentId: environment.id, ports: [{ port: 3000, ownerThreadId: "ports_a" }, { port: 8080, ownerThreadId: "" }] }];
  renderSlot(inbox, listProps, {
    sidebarThreads: {
      status: "ready",
      threads: [
        thread({ id: "ports_a", environment }),
        thread({ id: "ports_b", environment }),
        thread({ id: "no_ports" }),
      ],
      projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
    },
    rpc: {
      listLifecycle: () => ({ rows: [] }),
      getOpenPorts: () => ({ groups }),
    },
  });
  const label = "Open ports started by this thread";
  await waitFor(() => expect(screen.getAllByRole("img", { name: label })).toHaveLength(1));
  expect(screen.getByRole("img", { name: label }).textContent).toBe("");
  expect(screen.getByRole("img", { name: label }).className).toContain("text-muted-foreground/60");
  vi.useFakeTimers();
  // Trigger a fresh provider mount so its next poll uses the fake clock.
  cleanup();
  renderSlot(inbox, listProps, {
    sidebarThreads: { status: "ready", threads: [thread({ id: "ports_a", environment })], projects: [] },
    rpc: {
      listLifecycle: () => ({ rows: [] }),
      getOpenPorts: () => ({ groups }),
    },
  });
  await act(async () => {});
  expect(screen.getByRole("img", { name: label })).toBeTruthy();
  groups = [];
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(screen.queryByRole("img", { name: label })).toBeNull();
  cleanup();
  vi.useRealTimers();
});

function render(
  threads: PluginSidebarThread[],
  projects = [{ id: "proj_1", name: "bb", isPersonal: false }],
) {
  return renderSlot(inbox, listProps, {
    sidebarThreads: { status: "ready", threads, projects },
    providers: { status: "ready", providers: defaultProviders },
    // The lifecycle store is the plugin's own backend; an empty one means
    // every thread is active, which is what these list tests are about.
    rpc: { listLifecycle: () => ({ rows: [] }) },
  });
}


/**
 * The card's trailing slot and the two spans it stacks: the status, and the
 * park actions that replace it on a hover device. On touch both stay put, so
 * the tests need each span separately.
 */
function statusSlotParts(row: HTMLElement, statusText: string) {
  const status = within(row).getByText(statusText);
  const statusWrapper = status.parentElement!;
  const slot = statusWrapper.parentElement!;
  return {
    status,
    statusWrapper,
    slot,
    actions: slot.lastElementChild as HTMLElement,
  };
}

/**
 * Controls nested inside other controls. A `<button>` inside an `<a>` is
 * invalid interactive nesting and breaks keyboard behaviour, so every row that
 * mixes a navigation target with its own buttons must report none.
 */
function nestedInteractiveControls(root: HTMLElement): string[] {
  return Array.from(
    root.querySelectorAll("a a, a button, button a, button button"),
  ).map((element) => element.outerHTML);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

afterEach(() => {
  cleanup();
  window.localStorage.clear();
  toastMocks.success.mockReset();
  toastMocks.error.mockReset();
  vi.mocked(document.elementFromPoint).mockReset();
});

describe("BB Sidebar registration", () => {
  it("opens project settings and confirms project edits from the card menu", async () => {
    const renameProject = vi.fn(() => ({ ok: true }));
    const removeProject = vi.fn(() => ({ ok: true }));
    const addProjectPath = vi.fn(() => ({ ok: true }));
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: { status: "ready", threads: [thread({ title: "Project card" })], projects: [{ id: "proj_1", name: "bb", isPersonal: false }] },
      context: { projectId: "proj_other", threadId: "thr_other" },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        projectPathHosts: () => ({ hosts: [{ id: "host_2", name: "Laptop" }] }),
        renameProject, removeProject, addProjectPath,
      },
    });
    const openMenu = async () => {
      fireEvent.contextMenu(await screen.findByText("Project card"));
      fireEvent.click(screen.getByRole("menuitem", { name: "Project" }));
      return (await screen.findByText("Project settings")).closest<HTMLElement>('[role="menu"]')!;
    };
    const settingsMenu = await openMenu();
    expect(settingsMenu.hasAttribute("data-bb-plugin-root")).toBe(true);
    expect(within(settingsMenu).getByText("Project settings").getAttribute("href")).toBe("/projects/proj_1/settings");
    fireEvent.keyDown(settingsMenu, { key: "Escape" });

    fireEvent.click(within(await openMenu()).getByText("Rename project"));
    let dialog = await screen.findByRole("dialog", { name: "Rename project" });
    expect(dialog.hasAttribute("data-bb-plugin-root")).toBe(true);
    expect(dialog.hasAttribute("data-bb-portaled-overlay")).toBe(true);
    fireEvent.change(within(dialog).getByLabelText("Project name"), { target: { value: "Renamed" } });
    fireEvent.click(within(dialog).getByText("Save"));
    await waitFor(() => expect(renameProject).toHaveBeenCalledWith({ projectId: "proj_1", name: "Renamed" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    const menu = await openMenu();
    await waitFor(() => expect(within(menu).getByText("Add local path").getAttribute("data-disabled")).toBeNull());
    fireEvent.click(within(menu).getByText("Add local path"));
    dialog = await screen.findByRole("dialog", { name: "Add local path" });
    fireEvent.change(within(dialog).getByLabelText("Folder path"), { target: { value: "/workspace/bb" } });
    fireEvent.click(within(dialog).getByText("Save"));
    await waitFor(() => expect(addProjectPath).toHaveBeenCalledWith({ projectId: "proj_1", hostId: "host_2", path: "/workspace/bb" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    fireEvent.click(within(await openMenu()).getByText("Remove project"));
    dialog = await screen.findByRole("dialog", { name: "Remove project" });
    expect((within(dialog).getByRole("button", { name: "Remove project" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(within(dialog).getByText("Cancel"));
    expect(removeProject).not.toHaveBeenCalled();
    fireEvent.click(within(await openMenu()).getByText("Remove project"));
    dialog = await screen.findByRole("dialog", { name: "Remove project" });
    fireEvent.change(within(dialog).getByLabelText("Project name"), { target: { value: "bb" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Remove project" }));
    await waitFor(() => expect(removeProject).toHaveBeenCalledWith({ projectId: "proj_1", confirmation: "bb" }));
    expect(rendered.navigateCalls).toEqual([]);
  });

  it("registers exactly one thread list", () => {
    expect(app.threadLists).toHaveLength(1);
    expect(inbox.id).toBe("inbox");
    expect(inbox.title).toBe("BB Sidebar");
  });

  it("registers one custom settings page", () => {
    expect(app.settingsSections).toHaveLength(1);
    expect(sidebarSettings.id).toBe("sidebar-settings");
    expect(sidebarSettings.title).toBeUndefined();
  });
});

describe("sidebar settings", () => {
  it("lists device hosts in settings and saves the local port-link choice", async () => {
    renderSlot(sidebarSettings, {}, {
      sidebarThreads: { status: "ready", projects: [], threads: [thread({ host: { id: "host_local", name: "Local Mac" } })] },
      rpc: { getSidebarSettings: () => defaultSidebarSettings, listProjectIconSettings: () => ({ projects: [] }) },
    });
    const select = await screen.findByLabelText("Port links on this device");
    expect(within(select).getByRole("option", { name: "Local Mac" })).toBeDefined();
    fireEvent.change(select, { target: { value: "host_local" } });
    expect(localStorage.getItem("bb-sidebar:port-link-host:v1")).toBe("host_local");
  });
  it("groups related controls and saves them together", async () => {
    let saved: typeof defaultSidebarSettings | null = null;
    renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        updateSidebarSettings: (input) => {
          saved = input as typeof defaultSidebarSettings;
          return saved;
        },
        listProjectIconSettings: () => ({
          projects: [
            {
              id: "proj_1",
              name: "Sidebar",
              customPath: null,
              customUploadName: null,
            },
          ],
        }),
      },
    });

    expect(await screen.findByText("Thread organization")).toBeDefined();
    expect(screen.getByText("Automatic cleanup")).toBeDefined();
    expect(screen.getByText("Project icons")).toBeDefined();
    expect(
      screen
        .getByRole("switch", { name: "Inactive shelf" })
        .querySelector("span")?.className,
    ).toContain("left-0.5");
    expect(
      screen
        .getByRole("switch", { name: "Show children that need attention" })
        .getAttribute("aria-checked"),
    ).toBe("true");

    fireEvent.change(screen.getByLabelText("Snooze shortcuts"), {
      target: { value: "1h, Wait refresh=5h, Tonight=evening@20:00, Morning=tomorrow@08:30, Monday=next-week@10:00" },
    });
    fireEvent.click(
      screen.getByRole("switch", { name: "Show children that need attention" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(saved).toEqual({
        ...defaultSidebarSettings,
        snoozePresets: "1h, Wait refresh=5h, Tonight=evening@20:00, Morning=tomorrow@08:30, Monday=next-week@10:00",
        showRunningChildrenWhenCollapsed: false,
      }),
    );
  });

  it("blocks invalid settings and previews valid snooze shortcuts", async () => {
    renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        listProjectIconSettings: () => ({ projects: [] }),
      },
    });

    const snoozeInput = await screen.findByLabelText("Snooze shortcuts");
    const saveButton = screen.getByRole("button", { name: "Save changes" });
    fireEvent.change(snoozeInput, { target: { value: "later" } });
    expect(snoozeInput.getAttribute("aria-invalid")).toBe("true");
    expect(
      screen.getByText(
        "Use comma-separated durations or calendar times, such as 1h, Wait refresh=5h, evening@18:00, tomorrow@09:00, or next-week@09:00.",
      ),
    ).toBeDefined();
    expect((saveButton as HTMLButtonElement).disabled).toBe(true);

    fireEvent.change(snoozeInput, {
      target: { value: "15m, Lunch=3h" },
    });
    expect(screen.getByText("Menu: 15 minutes, Lunch")).toBeDefined();
    expect((saveButton as HTMLButtonElement).disabled).toBe(false);

    fireEvent.change(snoozeInput, { target: { value: "tomorrow@25:00" } });
    expect((saveButton as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(snoozeInput, { target: { value: "Morning=tomorrow@08:30" } });
    expect(screen.getByText("Menu: Morning")).toBeDefined();
    expect((saveButton as HTMLButtonElement).disabled).toBe(false);

    const inactiveHours = screen.getByLabelText("Hours before inactive");
    fireEvent.change(inactiveHours, { target: { value: "0" } });
    expect(inactiveHours.getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByText("Enter a whole number from 1 to 720.")).toBeDefined();
    expect((saveButton as HTMLButtonElement).disabled).toBe(true);
  });

  it("uploads a project icon from the file picker", async () => {
    let upload:
      | {
          projectId: string;
          filename: string;
          mimeType: string;
          contentBase64: string;
        }
      | null = null;
    renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        listProjectIconSettings: () => ({
          projects: [
            {
              id: "proj_1",
              name: "Sidebar",
              customPath: null,
              customUploadName: null,
            },
          ],
        }),
        uploadProjectIcon: (input) => {
          upload = input as typeof upload;
          return {
            customPath: null,
            customUploadName: "brand.svg",
          };
        },
      },
    });

    const picker = await screen.findByLabelText("Choose project icon image");
    fireEvent.change(picker, {
      target: {
        files: [new File(["<svg/>"], "brand.svg", { type: "image/svg+xml" })],
      },
    });
    await waitFor(() =>
      expect(upload).toEqual({
        projectId: "proj_1",
        filename: "brand.svg",
        mimeType: "image/svg+xml",
        contentBase64: "PHN2Zy8+",
      }),
    );
    expect(screen.getByText("brand.svg")).toBeDefined();
  });

  it("preserves unsaved settings when a realtime refresh arrives", async () => {
    let remoteSettings = defaultSidebarSettings;
    const rendered = renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => remoteSettings,
        listProjectIconSettings: () => ({ projects: [] }),
      },
    });

    const shortcuts = await screen.findByLabelText("Snooze shortcuts");
    fireEvent.change(shortcuts, { target: { value: "Local=45m" } });
    remoteSettings = { ...defaultSidebarSettings, inactiveAfterHours: 12 };

    await rendered.emitRealtime("sidebar-settings", {});

    expect((shortcuts as HTMLInputElement).value).toBe("Local=45m");
    expect(screen.getByText("Unsaved changes")).toBeDefined();
  });

  it("ignores an older project-icon load after a newer refresh", async () => {
    const older = deferred<{
      projects: Array<{
        id: string;
        name: string;
        customPath: null;
        customUploadName: null;
      }>;
    }>();
    let loads = 0;
    const rendered = renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        listProjectIconSettings: () => {
          loads += 1;
          return loads === 1
            ? older.promise
            : {
                projects: [
                  {
                    id: "new",
                    name: "Newest project",
                    customPath: null,
                    customUploadName: null,
                  },
                ],
              };
        },
      },
    });

    await waitFor(() => expect(loads).toBe(1));
    await rendered.emitRealtime("project-icons", {});
    expect(await screen.findByText("Newest project")).toBeDefined();

    older.resolve({
      projects: [
        {
          id: "old",
          name: "Stale project",
          customPath: null,
          customUploadName: null,
        },
      ],
    });
    await Promise.resolve();
    expect(screen.queryByText("Stale project")).toBeNull();
    expect(screen.getByText("Newest project")).toBeDefined();
  });

  it("requires a second inline click before removing a project", async () => {
    let removal: { projectId: string; confirmation: string } | null = null;
    renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        listProjectIconSettings: () => ({ projects: [] }),
        listProjects: () => ({
          projects: [{ id: "proj_1", name: "Sidebar" }],
        }),
        removeProject: (input) => {
          removal = input as typeof removal;
          return { ok: true as const };
        },
      },
    });

    expect(await screen.findByText("Projects")).toBeDefined();
    fireEvent.click(await screen.findByRole("button", { name: "Remove..." }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    const confirmation = screen.getByRole("group", {
      name: "Confirm removal of Sidebar",
    });
    expect(within(confirmation).getByText("Remove Sidebar?")).toBeDefined();
    expect(removal).toBeNull();

    fireEvent.click(
      within(confirmation).getByRole("button", { name: "Remove from BB" }),
    );

    await waitFor(() =>
      expect(removal).toEqual({
        projectId: "proj_1",
        confirmation: "Sidebar",
      }),
    );
    expect(await screen.findByText("No removable projects.")).toBeDefined();
    expect(toastMocks.success).toHaveBeenCalledWith("Sidebar removed from BB");
  });
});

describe("thread list loading state", () => {
  function renderStatus(status: "loading" | "error" | "ready") {
    return renderSlot(inbox, listProps, {
      sidebarThreads: {
        status,
        threads: status === "ready" ? [thread({ title: "Loaded thread" })] : [],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });
  }

  function loadingStatus() {
    return screen
      .queryAllByRole("status")
      .find((region) => region.textContent === "Loading threads…");
  }

  afterEach(() => {
    vi.useRealTimers();
  });

  it("stays quiet while a load is still fast", () => {
    vi.useFakeTimers();
    renderStatus("loading");
    act(() => vi.advanceTimersByTime(199));
    expect(screen.queryByText("Loading threads…")).toBeNull();
    expect(loadingStatus()).toBeUndefined();
  });

  it("shows a spinner and text once loading outlasts the delay", () => {
    vi.useFakeTimers();
    renderStatus("loading");
    const regionsBefore = screen.getAllByRole("status");
    act(() => vi.advanceTimersByTime(200));
    const region = loadingStatus();
    expect(region).toBeDefined();
    // The same live region was already mounted, empty, before the text came.
    expect(regionsBefore).toContain(region);
    const spinner = region!.querySelector('[data-icon="Loading"]');
    expect(spinner?.getAttribute("aria-hidden")).toBe("true");
    expect(screen.queryByText("Could not load threads.")).toBeNull();
  });

  it("reports a failed load without the loading indicator", () => {
    vi.useFakeTimers();
    renderStatus("error");
    act(() => vi.advanceTimersByTime(1_000));
    const region = screen
      .getAllByRole("status")
      .find((status) => status.textContent === "Could not load threads.");
    expect(region).toBeDefined();
    expect(screen.queryByText("Loading threads…")).toBeNull();
  });

  it("shows the list and no loading text once ready", () => {
    vi.useFakeTimers();
    renderStatus("ready");
    act(() => vi.advanceTimersByTime(1_000));
    expect(screen.getByText("Loaded thread")).toBeDefined();
    expect(screen.queryByText("Loading threads…")).toBeNull();
    expect(loadingStatus()).toBeUndefined();
  });
});

describe("ThreadInbox", () => {
  it("renders provider names, logos, and theme tints from bb's directory", () => {
    const view = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ providerId: "pi", title: "Pi thread" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      providers: {
        status: "ready",
        providers: [
          {
            id: "pi",
            pluginId: "provider-pi",
            displayName: "Pi",
            available: true,
            maintenance: {
              health: true,
              usage: false,
              installation: true,
            },
            logoUrl: "/api/v1/system/providers/pi/logo",
            capabilities: {
              modelCatalogScope: "workspace",
              permissionModes: ["full"],
              supportsFork: true,
              supportsNativeUserQuestion: false,
              supportsServiceTier: false,
              supportsSessionRewind: true,
              supportsThreadArchive: false,
              supportsThreadRename: false,
            },
            composerActions: [],
            strings: {
              signInHint: "Run pi to sign in.",
              expiredHint: "Run pi to sign in again.",
              installUrl: "https://pi.dev",
              iconTint: { light: "#6D5DFB", dark: "#A99EFF" },
            },
          },
        ],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const glyph = screen.getByRole("img", { name: "Pi" });
    const marks = glyph.querySelectorAll<HTMLElement>("[aria-hidden=true]");
    expect(marks).toHaveLength(2);
    expect(marks[0]!.style.maskImage).toContain(
      "/api/v1/system/providers/pi/logo",
    );
    expect(marks[0]!.style.backgroundColor).toBe("rgb(109, 93, 251)");
    expect(marks[1]!.style.backgroundColor).toBe("rgb(169, 158, 255)");
    expect(view.container.querySelector('[aria-label="pi"]')).toBeNull();
  });

  it("falls back to the provider id when the directory has no match", () => {
    render([thread({ providerId: "custom-agent" })]);

    const glyph = screen.getByRole("img", { name: "custom-agent" });
    expect(glyph.querySelector(".rounded-full")).not.toBeNull();
  });

  it("loads a project favicon beside the project name", async () => {
    const view = render([
      thread({
        id: "icon-thread",
        environment: {
          id: "env_1",
          name: "main",
          branchName: "main",
          workspaceDisplayKind: "other",
        },
      }),
    ]);

    const preload = await waitFor(() => {
      const image = view.container.querySelector<HTMLImageElement>(
        'img[src*="project-icon"]',
      );
      expect(image).not.toBeNull();
      return image!;
    });
    expect(preload.src).toContain("projectId=proj_1");
    expect(preload.src).not.toContain("environmentId");
    fireEvent.load(preload);
    expect(
      view.container.querySelector('img.object-contain[src*="project-icon"]'),
    ).not.toBeNull();
  });

  it("shows active threads in a collapsible Active shelf", () => {
    render([
      thread({ id: "a", title: "First active" }),
      thread({ id: "b", title: "Second active" }),
    ]);

    const activeShelf = screen.getByRole("region", { name: "Active" });
    expect(
      within(activeShelf).getByRole("button", { expanded: true }),
    ).toBeDefined();
    fireEvent.click(
      within(activeShelf).getByRole("button", { expanded: true }),
    );
    expect(within(activeShelf).getByText("Active (2)")).toBeDefined();
    expect(within(activeShelf).queryByText("First active")).toBeNull();
    expect(within(activeShelf).queryByText("Second active")).toBeNull();
  });

  it("keeps the currently open active row visible while collapsed", () => {
    renderSlot(inbox, { ...listProps, activeThreadId: "open" }, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "open", title: "Open active" }),
          thread({ id: "other", title: "Other active" }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const activeShelf = screen.getByRole("region", { name: "Active" });
    fireEvent.click(
      within(activeShelf).getByRole("button", { expanded: true }),
    );
    expect(within(activeShelf).getByText("Open active")).toBeDefined();
    expect(within(activeShelf).queryByText("Other active")).toBeNull();
  });

  it("moves stale unpinned threads to a collapsed Inactive shelf", () => {
    const now = Date.now();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "recent",
            title: "Recent work",
            updatedAt: now - 60 * 60 * 1_000,
          }),
          thread({
            id: "stale",
            title: "Stale work",
            updatedAt: now - 7 * 60 * 60 * 1_000,
          }),
          thread({
            id: "stale-pin",
            title: "Pinned old work",
            isPinned: true,
            updatedAt: now - 7 * 60 * 60 * 1_000,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: {
        inactiveThreadsEnabled: true,
        inactiveAfterHours: "6",
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const active = screen.getByRole("region", { name: "Active" });
    const inactive = screen.getByRole("region", { name: "Inactive" });
    const pinned = screen.getByRole("region", { name: "Pinned" });
    expect(within(active).getByText("Recent work")).toBeDefined();
    expect(within(active).queryByText("Stale work")).toBeNull();
    expect(within(inactive).getByText("Inactive (1)")).toBeDefined();
    expect(within(inactive).queryByText("Stale work")).toBeNull();
    expect(within(pinned).getByText("Pinned old work")).toBeDefined();

    fireEvent.click(
      within(inactive).getByRole("button", { expanded: false }),
    );
    expect(within(inactive).getByText("Stale work")).toBeDefined();
  });

  it("keeps stale threads Active when the feature is disabled", () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "stale",
            title: "Still active",
            updatedAt: Date.now() - 24 * 60 * 60 * 1_000,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: {
        inactiveThreadsEnabled: false,
        inactiveAfterHours: "6",
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    expect(
      within(screen.getByRole("region", { name: "Active" })).getByText(
        "Still active",
      ),
    ).toBeDefined();
    expect(screen.queryByRole("region", { name: "Inactive" })).toBeNull();
  });

  it("uses the configured inactivity threshold", () => {
    const now = Date.now();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "seven-hours",
            title: "Seven hours old",
            updatedAt: now - 7 * 60 * 60 * 1_000,
          }),
          thread({
            id: "nine-hours",
            title: "Nine hours old",
            updatedAt: now - 9 * 60 * 60 * 1_000,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: {
        inactiveThreadsEnabled: true,
        inactiveAfterHours: "8",
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    expect(
      within(screen.getByRole("region", { name: "Active" })).getByText(
        "Seven hours old",
      ),
    ).toBeDefined();
    expect(
      within(screen.getByRole("region", { name: "Inactive" })).getByText(
        "Inactive (1)",
      ),
    ).toBeDefined();
  });

  it("sorts active threads from the subtle header menu", async () => {
    render(
      [
        thread({
          id: "alpha-new",
          projectId: "proj_alpha",
          title: "Alpha new",
          createdAt: 3,
          updatedAt: 10,
        }),
        thread({
          id: "beta-new",
          projectId: "proj_beta",
          title: "Beta new",
          createdAt: 4,
          updatedAt: 30,
        }),
        thread({
          id: "alpha-old",
          projectId: "proj_alpha",
          title: "Alpha old",
          createdAt: 1,
          updatedAt: 40,
        }),
        thread({
          id: "beta-old",
          projectId: "proj_beta",
          title: "Beta old",
          createdAt: 2,
          updatedAt: 20,
        }),
      ],
      [
        { id: "proj_alpha", name: "Alpha", isPersonal: false },
        { id: "proj_beta", name: "Beta", isPersonal: false },
      ],
    );

    const activeShelf = screen.getByRole("region", { name: "Active" });
    const sortMenu = within(activeShelf).getByRole("combobox", {
      name: "Sort active threads: Manual order",
    });
    expect(sortMenu.querySelector('[data-icon="ArrowUpDown"]')).not.toBeNull();
    expect(sortMenu.classList.contains("focus:ring-0")).toBe(true);
    expect(sortMenu.classList.contains("focus-visible:ring-1")).toBe(true);
    expect(sortMenu.classList.contains("focus:ring-1")).toBe(false);
    expect(
      within(activeShelf)
        .getAllByRole("listitem")
        .map((row) => row.textContent),
    ).toEqual([
      expect.stringContaining("Beta new"),
      expect.stringContaining("Alpha new"),
      expect.stringContaining("Beta old"),
      expect.stringContaining("Alpha old"),
    ]);

    fireEvent.keyDown(sortMenu, { key: "Enter" });
    expect(screen.getByRole("option", { name: "Manual order" })).toBeDefined();
    expect(
      screen.getByRole("option", { name: "Recent activity" }),
    ).toBeDefined();
    expect(screen.getByRole("option", { name: "Date created" })).toBeDefined();
    expect(screen.getByRole("option", { name: "Project" })).toBeDefined();
    fireEvent.click(screen.getByRole("option", { name: "Recent activity" }));

    expect(
      within(activeShelf)
        .getAllByRole("listitem")
        .map((row) => row.textContent),
    ).toEqual([
      expect.stringContaining("Alpha old"),
      expect.stringContaining("Beta new"),
      expect.stringContaining("Beta old"),
      expect.stringContaining("Alpha new"),
    ]);
    expect(
      within(activeShelf)
        .getAllByRole("link")
        .every((link) => link.getAttribute("aria-keyshortcuts") === null),
    ).toBe(true);

    fireEvent.keyDown(
      within(activeShelf).getByRole("combobox", {
        name: "Sort active threads: Recent activity",
      }),
      { key: "Enter" },
    );
    fireEvent.click(screen.getByRole("option", { name: "Date created" }));
    expect(
      within(activeShelf)
        .getAllByRole("listitem")
        .map((row) => row.textContent),
    ).toEqual([
      expect.stringContaining("Beta new"),
      expect.stringContaining("Alpha new"),
      expect.stringContaining("Beta old"),
      expect.stringContaining("Alpha old"),
    ]);

    fireEvent.keyDown(
      within(activeShelf).getByRole("combobox", {
        name: "Sort active threads: Date created",
      }),
      { key: "Enter" },
    );
    fireEvent.click(screen.getByRole("option", { name: "Project" }));
    expect(
      within(activeShelf)
        .getAllByRole("listitem")
        .map((row) => row.textContent),
    ).toEqual([
      expect.stringContaining("Alpha new"),
      expect.stringContaining("Alpha old"),
      expect.stringContaining("Beta new"),
      expect.stringContaining("Beta old"),
    ]);
    expect(
      within(activeShelf).getByRole("list", {
        name: "Alpha active threads",
      }),
    ).toBeDefined();
    expect(
      within(activeShelf)
        .getByRole("list", { name: "Alpha active threads" })
        .classList.contains("border"),
    ).toBe(true);
    expect(
      within(activeShelf)
        .getAllByRole("link")
        .every(
          (link) =>
            link.getAttribute("aria-keyshortcuts") ===
            "Alt+ArrowUp Alt+ArrowDown",
        ),
    ).toBe(true);
    await waitFor(() =>
      expect(
        window.localStorage.getItem("bb-sidebar:active-sort:v1"),
      ).toBe("project"),
    );
  });

  it("migrates the previous project grouping preference", async () => {
    window.localStorage.setItem("bb-sidebar:active-grouping:v1", "true");
    render([thread({ id: "saved", title: "Saved grouping" })]);

    expect(
      screen.getByRole("combobox", {
        name: "Sort active threads: Project",
      }),
    ).toBeDefined();
    expect(
      screen.getByRole("list", { name: "bb active threads" }),
    ).toBeDefined();
    await waitFor(() =>
      expect(window.localStorage.getItem("bb-sidebar:active-sort:v1")).toBe(
        "project",
      ),
    );
  });

  it("outlines only project groups with more than one thread", () => {
    window.localStorage.setItem("bb-sidebar:active-sort:v1", "project");
    render(
      [
        thread({ id: "alpha-1", projectId: "alpha", title: "Alpha one" }),
        thread({ id: "alpha-2", projectId: "alpha", title: "Alpha two" }),
        thread({ id: "beta-1", projectId: "beta", title: "Beta one" }),
      ],
      [
        { id: "alpha", name: "Alpha", isPersonal: false },
        { id: "beta", name: "Beta", isPersonal: false },
      ],
    );

    const repeatedProject = screen.getByRole("list", {
      name: "Alpha active threads",
    });
    const singleThreadProject = screen.getByRole("list", {
      name: "Beta active threads",
    });
    expect(repeatedProject.classList.contains("border")).toBe(true);
    expect(repeatedProject.className).not.toContain("shadow");
    expect(repeatedProject.className).not.toContain("bg-");
    expect(singleThreadProject.classList.contains("border")).toBe(false);
    expect(singleThreadProject.classList.contains("p-px")).toBe(false);
  });

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

  it("shows a capped child badge only on parent cards", () => {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    render([
      thread({
        id: "parent",
        title: "Parent",
        host: { id: "host_1", name: "Dev MacBook" },
        environment: {
          id: "env_1",
          name: "Worktree",
          branchName: "main",
          workspaceDisplayKind: "managed-worktree",
        },
      }),
      thread({
        id: "child-1",
        title: "One",
        parentThreadId: "parent",
        updatedAt: minute - 60_000,
      }),
      thread({ id: "child-2", title: "Two", parentThreadId: "parent" }),
      thread({ id: "child-3", title: "Three", parentThreadId: "parent" }),
      thread({ id: "child-4", title: "Four", parentThreadId: "parent" }),
      thread({ id: "child-5", title: "Five", parentThreadId: "parent" }),
      thread({ id: "root", title: "No children" }),
    ]);

    const badge = screen.getByRole("button", { name: "5 child threads" });
    expect(badge.getAttribute("aria-expanded")).toBe("false");
    expect(badge.querySelectorAll("[data-child-thread-dot]")).toHaveLength(3);
    expect(badge.querySelector('[data-icon="ChevronDown"]')).not.toBeNull();
    const parentCard = badge.closest("li");
    expect(parentCard).not.toBeNull();
    const machine = within(parentCard!).getByLabelText("Machine: Dev MacBook");
    const providerGlyph = within(parentCard!).getByRole("img", {
      name: "Codex",
    });
    expect(
      badge.compareDocumentPosition(machine) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      machine.compareDocumentPosition(providerGlyph) &
        Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      screen.queryByRole("button", { name: /No children.*child/i }),
    ).toBeNull();
    expect(screen.queryByText("One")).toBeNull();
  });

  it("rolls the most urgent child state up into the parent badge", () => {
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "working",
        title: "Working child",
        parentThreadId: "parent",
        indicator: "runtime",
      }),
      thread({
        id: "done",
        title: "Done child",
        parentThreadId: "parent",
        indicator: "unread-success",
      }),
      thread({
        id: "quiet",
        title: "Quiet child",
        parentThreadId: "parent",
      }),
      thread({
        id: "failed-grandchild",
        title: "Failed grandchild",
        parentThreadId: "quiet",
        indicator: "unread-error",
      }),
    ]);

    const badge = screen.getByRole("button", {
      name: "3 child threads, 1 failed, 1 done, 1 working",
    });
    expect(badge.getAttribute("data-child-status")).toBe("failed");
    expect(badge.className).toContain(
      "bg-[color:var(--bb-sidebar-badge-failed-bg)]",
    );
    expect(badge.querySelector('[data-icon="CircleX"]')).not.toBeNull();
  });

  it("marks a badge with only working children as working", () => {
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "working",
        title: "Working child",
        parentThreadId: "parent",
        indicator: "runtime",
      }),
    ]);

    const badge = screen.getByRole("button", {
      name: "1 child thread, 1 working",
    });
    expect(badge.getAttribute("data-child-status")).toBe("working");
    expect(badge.className).toContain(
      "bg-[color:var(--bb-sidebar-badge-working-bg)]",
    );
    expect(badge.querySelector('[data-icon="Loading"]')).not.toBeNull();
    expect(screen.getByRole("list", { name: "Child threads" })).toBeDefined();
    expect(screen.getByText("Working child")).toBeDefined();
  });

  // The needs-you rollup lost its coverage when the expanded-rows test was
  // rewritten: a raised hand anywhere in the subtree outranks live work, and
  // the badge has to say so in its tone, its data attribute and its glyph.
  it("marks a badge whose most urgent child needs the user", () => {
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "working",
        title: "Working child",
        parentThreadId: "parent",
        indicator: "runtime",
      }),
      thread({
        id: "asking",
        title: "Asking child",
        parentThreadId: "parent",
        hasPendingInteraction: true,
        indicator: "waiting-for-input",
      }),
    ]);

    const badge = screen.getByRole("button", {
      name: "2 child threads, 1 need you, 1 working",
    });
    expect(badge.getAttribute("data-child-status")).toBe("needs-you");
    expect(badge.className).toContain(
      "bg-[color:var(--bb-sidebar-badge-needs-you-bg)]",
    );
    expect(badge.querySelector('[data-icon="CircleQuestion"]')).not.toBeNull();
    expect(badge.querySelector('[data-icon="Loading"]')).toBeNull();
  });

  it("keeps every child with a status visible while collapsed, and folds read ones", () => {
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "failed",
        title: "Failed child",
        parentThreadId: "parent",
        indicator: "unread-error",
      }),
      thread({
        id: "waiting",
        title: "Waiting child",
        parentThreadId: "parent",
        hasPendingInteraction: true,
        indicator: "waiting-for-input",
      }),
      thread({
        id: "unread",
        title: "Unread child",
        parentThreadId: "parent",
        indicator: "unread-success",
      }),
      thread({
        id: "working",
        title: "Working child",
        parentThreadId: "parent",
        indicator: "runtime",
      }),
      thread({ id: "idle", title: "Idle child", parentThreadId: "parent" }),
      // An idle child stays as the path to a grandchild that has news.
      thread({ id: "carrier", title: "Carrier child", parentThreadId: "parent" }),
      thread({
        id: "failed-grandchild",
        title: "Failed grandchild",
        parentThreadId: "carrier",
        indicator: "unread-error",
      }),
    ]);

    // Nothing was expanded: the list below is the collapsed view.
    const childList = screen.getByRole("list", { name: "Child threads" });
    for (const title of [
      "Failed child",
      "Waiting child",
      "Unread child",
      "Working child",
      "Carrier child",
    ]) {
      expect(within(childList).getByText(title)).toBeDefined();
    }
    expect(within(childList).queryByText("Idle child")).toBeNull();
    expect(
      within(
        screen.getByRole("list", { name: "Grandchildren of Carrier child" }),
      ).getByText("Failed grandchild"),
    ).toBeDefined();
    expect(
      screen.getByRole("button", { name: /6 child threads/ })
        .getAttribute("aria-expanded"),
    ).toBe("false");
  });

  it("can hide children that need attention while their section is collapsed", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "parent", title: "Parent" }),
          thread({
            id: "working",
            title: "Working child",
            parentThreadId: "parent",
            indicator: "runtime",
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        getSidebarSettings: () => ({
          ...defaultSidebarSettings,
          showRunningChildrenWhenCollapsed: false,
        }),
        listLifecycle: () => ({ rows: [] }),
      },
    });

    await waitFor(() =>
      expect(
        screen.queryByRole("list", { name: "Child threads" }),
      ).toBeNull(),
    );
  });

  it("highlights the active grandchild row", () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "grandchild" },
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
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const childRow = screen.getByRole("button", {
      name: "Open child thread: Child",
    });
    expect(childRow.getAttribute("aria-current")).toBeNull();
    const grandchildRow = screen.getByRole("button", {
      name: "Open grandchild thread: Grandchild",
    });
    expect(grandchildRow.getAttribute("aria-current")).toBe("page");
    expect(
      grandchildRow.closest("[data-child-thread-row]")?.className,
    ).toContain("bg-sidebar-accent");
  });

  it("shows every child status or an idle age in expanded rows and accessible names", async () => {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({
        monitoring: minute - 5 * 60_000,
        planning: minute - 5 * 60_000,
      }),
    );
    const rendered = render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "failed",
        title: "Failed child",
        parentThreadId: "parent",
        indicator: "unread-error",
      }),
      thread({
        id: "unread",
        title: "Unread child",
        parentThreadId: "parent",
        indicator: "unread-success",
      }),
      thread({
        id: "waiting",
        title: "Waiting child",
        parentThreadId: "parent",
        indicator: "waiting-for-input",
      }),
      thread({
        id: "monitoring",
        title: "Monitoring child",
        parentThreadId: "parent",
        indicator: "runtime",
        indicatorLabel: "Thread monitoring",
      }),
      thread({
        id: "planning",
        title: "Planning child",
        parentThreadId: "parent",
        indicator: "plan-mode",
        activity: {
          workflows: 0,
          backgroundAgents: 0,
          backgroundCommands: 0,
          planMode: 1,
          goals: 0,
        },
      }),
      thread({
        id: "pending-runtime",
        title: "Pending runtime child",
        parentThreadId: "parent",
        hasPendingInteraction: true,
        indicator: "runtime",
        indicatorLabel: "Agent is working",
      }),
      thread({
        id: "idle",
        title: "Idle child",
        parentThreadId: "parent",
        updatedAt: minute - 31 * 60_000,
      }),
    ]);

    const badge = screen.getByRole("button", {
      name: "7 child threads, 1 failed, 2 need you, 1 done, 2 working",
    });
    fireEvent.click(badge);

    expect(badge.getAttribute("aria-expanded")).toBe("true");
    expect(badge.querySelector('[data-icon="ChevronUp"]')).not.toBeNull();
    const childList = screen.getByRole("list", { name: "Child threads" });
    expect(childList.getAttribute("data-child-thread-list")).toBe("sidebar");
    for (const label of [
      "Failed",
      "Unread",
      "Monitoring · 5m",
      "Planning · 5m",
    ]) {
      expect(within(childList).getByText(label)).toBeDefined();
    }
    expect(within(childList).getAllByText("Needs you")).toHaveLength(2);
    expect(within(childList).getByText("31m")).toBeDefined();
    expect(within(childList).queryByText("Agent is working")).toBeNull();

    for (const name of [
      "Open child thread: Failed child, Failed",
      "Open child thread: Unread child, Unread",
      "Open child thread: Waiting child, Needs you",
      "Open child thread: Monitoring child, Monitoring · 5m",
      "Open child thread: Planning child, Planning · 5m",
      "Open child thread: Pending runtime child, Needs you",
      "Open child thread: Idle child",
    ]) {
      expect(within(childList).getByRole("button", { name })).toBeDefined();
    }
    // Tint plus a leading rule: in dark the amber fill is only a 1.07:1 step
    // off the sidebar, so the rule is what actually finds the row.
    const needsYouRow = within(childList).getByRole("button", {
      name: "Open child thread: Pending runtime child, Needs you",
    }).parentElement!;
    expect(needsYouRow.className).toContain(
      "bg-[color:var(--bb-sidebar-needs-you-tint)]",
    );
    expect(needsYouRow.className).toContain(
      "shadow-[inset_2px_0_0_0_var(--bb-sidebar-needs-you-accent)]",
    );
    // and only that row: the rule is the tint's partner, not a row border.
    expect(
      within(childList).getByRole("button", {
        name: "Open child thread: Failed child, Failed",
      }).parentElement?.className,
    ).not.toContain("--bb-sidebar-needs-you-accent");

    // The slot takes exactly the width its label needs, up to the 112px the
    // longest status wants, so a short status or age hands the rest back to a
    // child title that a narrow sidebar has little room for.
    const monitoringSlot = within(childList).getByText("Monitoring · 5m")
      .parentElement!;
    expect(monitoringSlot.className).toContain("w-auto");
    expect(monitoringSlot.className).toContain("max-w-28");
    expect(monitoringSlot.className.split(" ")).not.toContain("w-28");
    expect(monitoringSlot.className.split(" ")).not.toContain("min-w-20");
    const idleSlot = within(childList).getByText("31m").parentElement!;
    expect(idleSlot.className).toContain("w-auto");
    expect(idleSlot.className.split(" ")).not.toContain("min-w-20");

    fireEvent.click(
      within(childList).getByRole("button", {
        name: "Open child thread: Monitoring child, Monitoring · 5m",
      }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "monitoring",
      options: { split: false },
    });
    await waitFor(() =>
      expect(
        JSON.parse(
          window.localStorage.getItem("bb-sidebar:child-expansion:v1") ?? "[]",
        ),
      ).toEqual(["parent"]),
    );
  });

  // bb adds indicator kinds over time. One this build has never seen has to
  // fall through to the age on a child row exactly as it does on a parent
  // card, and must not tint the rollup badge either.
  it("keeps the age on child and grandchild rows with an unrecognized indicator", () => {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "child",
        title: "Future child",
        parentThreadId: "parent",
        indicator: "something-bb-ships-later" as never,
        indicatorLabel: "Doing something new",
        updatedAt: minute - 4 * 60_000,
      }),
      thread({
        id: "grandchild",
        title: "Future grandchild",
        parentThreadId: "child",
        indicator: "another-thing-bb-ships-later" as never,
        indicatorLabel: "Also new",
        updatedAt: minute - 7 * 60_000,
      }),
    ]);

    const badge = screen.getByRole("button", { name: "1 child thread" });
    expect(badge.getAttribute("data-child-status")).toBeNull();
    expect(badge.className).toContain("bg-muted");
    fireEvent.click(badge);

    const childList = screen.getByRole("list", { name: "Child threads" });
    expect(within(childList).getByText("4m")).toBeDefined();
    expect(within(childList).queryByText("Doing something new")).toBeNull();
    expect(
      within(childList).getByRole("button", {
        name: "Open child thread: Future child",
      }),
    ).toBeDefined();

    fireEvent.click(
      within(childList).getByRole("button", {
        name: "Show 1 grandchild thread for Future child",
      }),
    );
    const grandchildList = screen.getByRole("list", {
      name: "Grandchildren of Future child",
    });
    expect(within(grandchildList).getByText("7m")).toBeDefined();
    expect(within(grandchildList).queryByText("Also new")).toBeNull();
    expect(
      within(grandchildList).getByRole("button", {
        name: "Open grandchild thread: Future grandchild",
      }),
    ).toBeDefined();
  });

  // Grandchildren are rows like any other: they get the same vocabulary, and
  // the status sits beside the disclosure button rather than displacing it.
  it("shows the shared status on grandchild rows and beside a disclosure", () => {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ child: minute - 5 * 60_000 }),
    );
    const rendered = render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "child",
        title: "Busy child",
        parentThreadId: "parent",
        indicator: "runtime",
      }),
      thread({
        id: "failed-grandchild",
        title: "Failed grandchild",
        parentThreadId: "child",
        indicator: "unread-error",
        indicatorLabel: "Unread thread failed",
      }),
      thread({
        id: "asking-grandchild",
        title: "Asking grandchild",
        parentThreadId: "child",
        hasPendingInteraction: true,
        indicator: "runtime",
        indicatorLabel: "Agent is working",
      }),
    ]);

    fireEvent.click(
      screen.getByRole("button", {
        name: "1 child thread, 1 failed, 1 need you, 1 working",
      }),
    );
    const childList = screen.getByRole("list", { name: "Child threads" });
    const childRow = within(childList)
      .getByRole("button", { name: "Open child thread: Busy child, Working · 5m" })
      .closest("[data-child-thread-row]") as HTMLElement;
    const disclosure = within(childRow).getByRole("button", {
      name: "Show 2 grandchild threads for Busy child",
    });
    expect(within(childRow).getByText("Working · 5m")).toBeDefined();
    fireEvent.click(disclosure);

    const grandchildList = screen.getByRole("list", {
      name: "Grandchildren of Busy child",
    });
    expect(within(grandchildList).getByText("Failed")).toBeDefined();
    expect(within(grandchildList).getByText("Needs you")).toBeDefined();
    // A raised hand outranks the runtime bb still reports for that thread.
    expect(within(grandchildList).queryByText(/^Working/)).toBeNull();
    for (const name of [
      "Open grandchild thread: Failed grandchild, Failed",
      "Open grandchild thread: Asking grandchild, Needs you",
    ]) {
      expect(within(grandchildList).getByRole("button", { name })).toBeDefined();
    }

    fireEvent.click(
      within(grandchildList).getByRole("button", {
        name: "Open grandchild thread: Failed grandchild, Failed",
      }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "failed-grandchild",
      options: { split: false },
    });
  });

  it("retains the newest child expansions after saving and remounting", async () => {
    const key = "bb-sidebar:child-expansion:v1";
    const oldIds = Array.from({ length: 100 }, (_, index) => `z${String(index).padStart(3, "0")}`);
    const allThreads = [...oldIds, "a-newest", "b-next"].flatMap((id) => [
      thread({ id, title: id }),
      thread({ id: `${id}-child`, title: `${id}-child`, parentThreadId: id }),
    ]);
    localStorage.setItem(key, JSON.stringify(oldIds));
    const first = render(allThreads);
    const expand = (id: string) => {
      const card = screen.getByRole("link", { name: id }).closest("li")!;
      fireEvent.click(within(card).getByRole("button", { name: "1 child thread" }));
    };
    expand("a-newest");
    await waitFor(() => expect(JSON.parse(localStorage.getItem(key)!)).toHaveLength(100));
    first.lifecycle.unmount();

    render(allThreads);
    expand("b-next");
    await waitFor(() => expect(JSON.parse(localStorage.getItem(key)!)).toEqual([
      ...oldIds.slice(2), "a-newest", "b-next",
    ]));
    // 200 threads rendered twice: the default 5s budget leaves this stress
    // case no headroom on a loaded CI runner.
  }, 30_000);

  it("restores child expansion outside the parent card body", () => {
    window.localStorage.setItem(
      "bb-sidebar:child-expansion:v1",
      JSON.stringify(["parent"]),
    );
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({ id: "child", title: "Child", parentThreadId: "parent" }),
    ]);

    expect(screen.getByRole("list", { name: "Child threads" })).toBeDefined();
    const childList = screen.getByRole("list", { name: "Child threads" });
    expect(childList.closest("[data-parent-card]")).toBeNull();
  });

  it("reveals the active child without persisted expansion", () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "child" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({ id: "child", title: "Child", parentThreadId: "parent" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    expect(screen.getByRole("list", { name: "Child threads" })).toBeDefined();
    expect(screen.getByText("Child")).toBeDefined();
  });

  it("collapses a parent while its child is active, keeping only that child visible", () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "child-a" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({ id: "child-a", title: "Child A", parentThreadId: "parent" }),
            thread({ id: "child-b", title: "Child B", parentThreadId: "parent" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const badge = screen.getByRole("button", { name: "2 child threads" });
    expect(badge.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText("Child A")).toBeDefined();
    expect(screen.queryByText("Child B")).toBeNull();
    const activeRow = screen.getByRole("button", {
      name: "Open child thread: Child A",
    });
    expect(activeRow.getAttribute("aria-current")).toBe("page");
    expect(activeRow.closest("[data-child-thread-row]")?.className).toContain(
      "bg-sidebar-accent",
    );

    fireEvent.click(badge);
    expect(badge.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText("Child A")).toBeDefined();
    expect(screen.getByText("Child B")).toBeDefined();

    fireEvent.click(badge);
    expect(badge.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText("Child A")).toBeDefined();
    expect(screen.queryByText("Child B")).toBeNull();
  });

  it("collapses a grandchild disclosure while a grandchild is active", () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "grandchild-a" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({ id: "child", title: "Child", parentThreadId: "parent" }),
            thread({
              id: "grandchild-a",
              title: "Grandchild A",
              parentThreadId: "child",
            }),
            thread({
              id: "grandchild-b",
              title: "Grandchild B",
              parentThreadId: "child",
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const disclosure = screen.getByRole("button", {
      name: "Show 2 grandchild threads for Child",
    });
    expect(disclosure.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText("Grandchild A")).toBeDefined();
    expect(screen.queryByText("Grandchild B")).toBeNull();

    fireEvent.click(disclosure);
    expect(disclosure.getAttribute("aria-expanded")).toBe("true");
    expect(screen.getByText("Grandchild B")).toBeDefined();

    fireEvent.click(disclosure);
    expect(disclosure.getAttribute("aria-expanded")).toBe("false");
    expect(screen.getByText("Grandchild A")).toBeDefined();
    expect(screen.queryByText("Grandchild B")).toBeNull();
  });

  it("keeps an active child's parked parent visible on a collapsed shelf", async () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "child" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parked parent" }),
            thread({ id: "child", title: "Active child", parentThreadId: "parent" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({
            rows: [
              {
                threadId: "parent",
                settledAt: 200,
                snoozedUntil: null,
                snoozedAt: null,
              },
            ],
          }),
        },
      },
    );

    const settled = await screen.findByRole("region", { name: "Settled" });
    expect(
      within(settled).getByRole("button", { expanded: false }),
    ).toBeDefined();
    expect(within(settled).getByText("Parked parent")).toBeDefined();
  });

  it("reveals the active grandchild and its child disclosure", () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "grandchild" },
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
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    expect(
      screen.getByRole("list", { name: "Grandchildren of Child" }),
    ).toBeDefined();
    expect(screen.getByText("Grandchild")).toBeDefined();
  });

  it("prunes expansion state for parents that no longer have children", async () => {
    window.localStorage.setItem(
      "bb-sidebar:child-expansion:v1",
      JSON.stringify(["parent", "deleted-parent"]),
    );
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({ id: "child", title: "Child", parentThreadId: "parent" }),
    ]);

    await waitFor(() =>
      expect(
        JSON.parse(
          window.localStorage.getItem("bb-sidebar:child-expansion:v1") ?? "[]",
        ),
      ).toEqual(["parent"]),
    );
  });

  it("archives the selected child instead of its parent", async () => {
    const rendered = render([
      thread({ id: "parent", title: "Parent" }),
      thread({ id: "child", title: "Child", parentThreadId: "parent" }),
    ]);
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
    expect(rendered.sidebarActionCalls).not.toContainEqual({
      method: "archive",
      threadId: "parent",
    });
  });

  it("releases the agent sessions archive leaves loaded", async () => {
    const rendered = render([
      thread({ id: "parent", title: "Parent" }),
      thread({ id: "idle-child", title: "Idle child", parentThreadId: "parent" }),
      thread({
        id: "busy-child",
        title: "Busy child",
        parentThreadId: "parent",
        indicator: "runtime",
      }),
      thread({ id: "stranger", title: "Stranger" }),
    ]);

    fireEvent.contextMenu(screen.getByText("Parent"));
    fireEvent.click(
      within(await screen.findByRole("menu", { name: "Thread actions" })).getByText(
        "Archive",
      ),
    );

    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "archive",
      threadId: "parent",
    });
    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "releaseRuntimes",
        input: { threadIds: ["parent", "idle-child"] },
      }),
    );
  });

  for (const busyChild of [
    thread({ id: "running", title: "Running child", indicator: "runtime" }),
    thread({
      id: "needs-input",
      title: "Needs input child",
      hasPendingInteraction: true,
    }),
  ]) {
    it(`disables Archive for a busy child: ${busyChild.id}`, async () => {
      render([
        thread({ id: "parent", title: "Parent" }),
        { ...busyChild, parentThreadId: "parent" },
      ]);
      fireEvent.click(screen.getByRole("button", { name: /^1 child thread/ }));
      fireEvent.contextMenu(
        screen.getByRole("button", {
          name: `Open child thread: ${busyChild.title}${
            busyChild.hasPendingInteraction ? ", Needs you" : ", Working"
          }`,
        }),
      );

      const archive = within(
        await screen.findByRole("menu", { name: "Thread actions" }),
      ).getByText("Archive");
      expect(archive.getAttribute("data-disabled")).not.toBeNull();
    });
  }

  it("shows one collapsed grandchild level without changing the parent count", () => {
    const rendered = render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "child",
        title: "Child",
        parentThreadId: "parent",
      }),
      thread({
        id: "grandchild",
        title: "Grandchild",
        parentThreadId: "child",
      }),
      thread({
        id: "great-grandchild",
        title: "Great-grandchild",
        parentThreadId: "grandchild",
      }),
    ]);

    const parentBadge = screen.getByRole("button", {
      name: "1 child thread",
    });
    fireEvent.click(parentBadge);

    const childList = screen.getByRole("list", { name: "Child threads" });
    expect(within(childList).getByText("Child")).toBeDefined();
    expect(screen.queryByText("Grandchild")).toBeNull();
    expect(screen.queryByText("Great-grandchild")).toBeNull();

    const disclosure = within(childList).getByRole("button", {
      name: "Show 1 grandchild thread for Child",
    });
    expect(disclosure.getAttribute("aria-expanded")).toBe("false");
    expect(disclosure.querySelector('[data-icon="ChevronDown"]')).not.toBeNull();

    fireEvent.click(disclosure);

    const grandchildList = screen.getByRole("list", {
      name: "Grandchildren of Child",
    });
    expect(grandchildList.getAttribute("data-grandchild-thread-list")).toBe(
      "sidebar",
    );
    expect(within(grandchildList).getByText("Grandchild")).toBeDefined();
    expect(screen.queryByText("Great-grandchild")).toBeNull();
    expect(disclosure.getAttribute("aria-expanded")).toBe("true");
    expect(disclosure.querySelector('[data-icon="ChevronUp"]')).not.toBeNull();

    fireEvent.click(
      within(grandchildList).getByRole("button", {
        name: "Open grandchild thread: Grandchild",
      }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "grandchild",
      options: { split: false },
    });
  });

  it("removes archived children from the sidebar badge and list", () => {
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "visible-child",
        title: "Visible child",
        parentThreadId: "parent",
      }),
      thread({
        id: "archived-child",
        title: "Archived child",
        parentThreadId: "parent",
        isArchived: true,
      }),
    ]);

    fireEvent.click(screen.getByRole("button", { name: "1 child thread" }));
    expect(screen.getByText("Visible child")).toBeDefined();
    expect(screen.queryByText("Archived child")).toBeNull();
  });

  it("opens a thread normally when the platform modifier is held", () => {
    const rendered = render([thread({ id: "thr_modifier" })]);
    fireEvent.click(screen.getByRole("link"), { metaKey: true });

    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "thr_modifier",
      options: { split: false },
    });
    expect(
      screen.queryByRole("toolbar", { name: /threads selected/ }),
    ).toBeNull();
  });

  it("keeps a separate collapsible Pinned shelf above Active", () => {
    render([
      thread({ id: "a", title: "Plain" }),
      thread({ id: "b", title: "Stuck", isPinned: true }),
    ]);

    const active = screen.getByRole("region", { name: "Active" });
    const pinned = screen.getByRole("region", { name: "Pinned" });
    expect(
      pinned.compareDocumentPosition(active) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(within(active).queryByText("Inbox")).toBeNull();
    expect(within(active).getByText("Plain")).toBeDefined();
    expect(within(active).queryByText("Stuck")).toBeNull();
    expect(within(pinned).getByText("Stuck")).toBeDefined();
    fireEvent.click(within(pinned).getByRole("button", { expanded: true }));
    expect(within(pinned).getByText("Pinned (1)")).toBeDefined();
    expect(within(pinned).queryByText("Stuck")).toBeNull();
    expect(within(active).getByText("Plain")).toBeDefined();
  });

  it("keeps pinned threads in the host's persisted order", () => {
    render([
      thread({ id: "first", title: "First pin", isPinned: true, createdAt: 1 }),
      thread({ id: "second", title: "Second pin", isPinned: true, createdAt: 999 }),
    ]);
    const pinned = screen.getByRole("region", { name: "Pinned" });
    expect(
      within(pinned).getAllByRole("listitem").map((row) => row.textContent),
    ).toEqual([
      expect.stringContaining("First pin"),
      expect.stringContaining("Second pin"),
    ]);
  });

  it("reorders pinned threads with the keyboard and persists the neighbors", async () => {
    let reorderInput: unknown = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
          thread({ id: "c", title: "Pin C", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        reorderPinned: (input) => {
          reorderInput = input;
          return { pinnedThreadIds: ["b", "a", "c"] };
        },
      },
    });

    const pinB = await screen.findByRole("link", { name: "Pin B" });
    fireEvent.keyDown(pinB, { key: "ArrowUp" });
    expect(reorderInput).toBeNull();
    fireEvent.keyDown(pinB, { key: "ArrowUp", altKey: true });
    await waitFor(() =>
      expect(reorderInput).toEqual({
        threadId: "b",
        previousThreadId: null,
        nextThreadId: "a",
      }),
    );
    const pinned = screen.getByRole("region", { name: "Pinned" });
    expect(
      within(pinned).getAllByRole("listitem").map((row) => row.textContent),
    ).toEqual([
      expect.stringContaining("Pin B"),
      expect.stringContaining("Pin A"),
      expect.stringContaining("Pin C"),
    ]);
  });

  it("reorders by dragging the card and exposes no grip control", async () => {
    let reorderInput: unknown = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
          thread({ id: "c", title: "Pin C", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        reorderPinned: (input) => {
          reorderInput = input;
          return { pinnedThreadIds: ["b", "a", "c"] };
        },
      },
    });

    const card = await screen.findByRole("link", { name: "Pin A" });
    const target = screen.getByText("Pin B").closest("li")!;
    vi.mocked(document.elementFromPoint).mockReturnValue(target);
    vi.spyOn(target, "getBoundingClientRect").mockReturnValue({
      top: 0,
      bottom: 40,
      left: 0,
      right: 200,
      width: 200,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });

    expect(card.draggable).toBe(false);
    expect(
      screen.queryByRole("button", { name: /Reorder Pin A/ }),
    ).toBeNull();
    expect(card.dataset.sidebarThreadId).toBe("a");
    fireEvent.pointerDown(card, {
      button: 0,
      clientX: 20,
      clientY: 0,
      pointerId: 1,
    });
    fireEvent.pointerMove(window, {
      buttons: 1,
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });
    fireEvent.pointerUp(window, {
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });
    await waitFor(() =>
      expect(reorderInput).toEqual({
        threadId: "a",
        previousThreadId: "b",
        nextThreadId: "c",
      }),
    );
  });

  it("cancels shelf reordering when bb takes over a split drag", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
      },
    });

    const card = await screen.findByRole("link", { name: "Pin A" });
    const target = screen.getByText("Pin B").closest("li")!;
    vi.mocked(document.elementFromPoint).mockReturnValue(target);
    vi.spyOn(target, "getBoundingClientRect").mockReturnValue({
      top: 0,
      bottom: 40,
      left: 0,
      right: 200,
      width: 200,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });

    fireEvent.pointerDown(card, {
      button: 0,
      clientX: 20,
      clientY: 0,
      pointerId: 1,
    });
    fireEvent.pointerMove(window, {
      buttons: 1,
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });
    await waitFor(() =>
      expect(
        within(screen.getByRole("region", { name: "Pinned" }))
          .getAllByRole("listitem")[0]!.textContent,
      ).toContain("Pin B"),
    );

    fireEvent.keyDown(window, { key: "Escape" });
    fireEvent.pointerUp(window, {
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });

    await waitFor(() =>
      expect(
        within(screen.getByRole("region", { name: "Pinned" }))
          .getAllByRole("listitem")[0]!.textContent,
      ).toContain("Pin A"),
    );
    expect(
      rendered.rpcCalls.filter((call) => call.method === "reorderPinned"),
    ).toHaveLength(0);
  });

  it("stops suppressing clicks once the drag's own click is swallowed", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const card = await screen.findByRole("link", { name: "Pin A" });
    const target = screen.getByText("Pin B").closest("li")!;
    vi.mocked(document.elementFromPoint).mockReturnValue(target);
    vi.spyOn(target, "getBoundingClientRect").mockReturnValue({
      top: 0,
      bottom: 40,
      left: 0,
      right: 200,
      width: 200,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });

    fireEvent.pointerDown(card, {
      button: 0,
      clientX: 20,
      clientY: 0,
      pointerId: 1,
    });
    fireEvent.pointerMove(window, {
      buttons: 1,
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });
    fireEvent.pointerUp(window, {
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });

    const openCalls = () =>
      rendered.sidebarActionCalls.filter((call) => call.method === "open")
        .length;
    const settled = openCalls();

    // The gesture's own click.
    fireEvent.click(card);
    expect(openCalls()).toBe(settled);

    // Enter on the same row raises a click with no pointer press in front of
    // it. Staying armed would swallow that one too, indefinitely.
    fireEvent.click(card);
    expect(openCalls()).toBe(settled + 1);
  });

  it("announces the new position after a keyboard reorder", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        reorderPinned: () => ({ pinnedThreadIds: ["b", "a"] }),
      },
    });

    const card = await screen.findByRole("link", { name: "Pin A" });
    fireEvent.keyDown(card, { key: "ArrowDown", altKey: true });
    expect(screen.getByText("Pin A moved to 2 of 2 in Pinned")).toBeDefined();

    // The row is last now, so the same key is a no-op — and silence would leave
    // a keyboard user unsure whether the press registered at all.
    await waitFor(() =>
      expect(
        within(screen.getByRole("region", { name: "Pinned" }))
          .getAllByRole("listitem")[0]!.textContent,
      ).toContain("Pin B"),
    );
    fireEvent.keyDown(card, { key: "ArrowDown", altKey: true });
    await waitFor(() =>
      expect(screen.getByText("Pin A is already last in Pinned")).toBeDefined(),
    );
  });

  it("leaves a touch gesture to the scroller instead of reordering", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const card = await screen.findByRole("link", { name: "Pin A" });
    const target = screen.getByText("Pin B").closest("li")!;
    vi.mocked(document.elementFromPoint).mockReturnValue(target);

    fireEvent.pointerDown(card, {
      button: 0,
      clientX: 20,
      clientY: 0,
      pointerId: 1,
      pointerType: "touch",
    });
    fireEvent.pointerMove(window, {
      buttons: 1,
      clientX: 20,
      clientY: 30,
      pointerId: 1,
      pointerType: "touch",
    });
    fireEvent.pointerUp(window, {
      clientX: 20,
      clientY: 30,
      pointerId: 1,
      pointerType: "touch",
    });

    expect(
      rendered.rpcCalls.filter((call) => call.method === "reorderPinned"),
    ).toHaveLength(0);
    expect(
      within(screen.getByRole("region", { name: "Pinned" }))
        .getAllByRole("listitem")[0]!.textContent,
    ).toContain("Pin A");
  });

  it("does not open the thread when a drag is cancelled with Escape", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const card = await screen.findByRole("link", { name: "Pin A" });
    const target = screen.getByText("Pin B").closest("li")!;
    vi.mocked(document.elementFromPoint).mockReturnValue(target);
    vi.spyOn(target, "getBoundingClientRect").mockReturnValue({
      top: 0,
      bottom: 40,
      left: 0,
      right: 200,
      width: 200,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });

    fireEvent.pointerDown(card, {
      button: 0,
      clientX: 20,
      clientY: 0,
      pointerId: 1,
    });
    fireEvent.pointerMove(window, {
      buttons: 1,
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });
    fireEvent.keyDown(window, { key: "Escape" });
    fireEvent.pointerUp(window, {
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });
    const openedBeforeClick = rendered.sidebarActionCalls.filter(
      (call) => call.method === "open",
    ).length;
    // The browser raises this once the gesture ends. Cancelling a drag must not
    // navigate into the row the drag started from.
    fireEvent.click(card);

    expect(
      rendered.sidebarActionCalls.filter((call) => call.method === "open"),
    ).toHaveLength(openedBeforeClick);
  });

  it("drops against the inbox order the host pushed mid-drag", async () => {
    const now = Date.now();
    let storedIds = ["a", "b", "z"];
    let reorderInput: { inboxThreadIds: string[] } | null = null;
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "a",
            title: "Inbox A",
            createdAt: 3,
            updatedAt: now - 60 * 60 * 1_000,
          }),
          thread({
            id: "b",
            title: "Inbox B",
            createdAt: 2,
            updatedAt: now - 60 * 60 * 1_000,
          }),
          // Inactive, so it holds a slot in the saved order without being a
          // drop target. That is what makes a stale base observable.
          thread({
            id: "z",
            title: "Inbox Z",
            createdAt: 1,
            updatedAt: now - 7 * 60 * 60 * 1_000,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: {
        inactiveThreadsEnabled: true,
        inactiveAfterHours: "6",
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        listInboxOrder: () => ({ inboxThreadIds: storedIds }),
        reorderInbox: (input) => {
          const parsed = input as { inboxThreadIds: string[] };
          reorderInput = parsed;
          return { inboxThreadIds: parsed.inboxThreadIds };
        },
      },
    });

    const card = await screen.findByRole("link", { name: "Inbox A" });
    const target = screen.getByText("Inbox B").closest("li")!;
    vi.mocked(document.elementFromPoint).mockReturnValue(target);
    vi.spyOn(target, "getBoundingClientRect").mockReturnValue({
      top: 0,
      bottom: 40,
      left: 0,
      right: 200,
      width: 200,
      height: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });

    fireEvent.pointerDown(card, {
      button: 0,
      clientX: 20,
      clientY: 0,
      pointerId: 1,
    });
    fireEvent.pointerMove(window, {
      buttons: 1,
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });

    storedIds = ["z", "a", "b"];
    await rendered.emitRealtime("inbox-order", {});

    fireEvent.pointerUp(window, {
      clientX: 20,
      clientY: 30,
      pointerId: 1,
    });

    // Merged against ["z", "a", "b"]. Against the pointer-down base it would
    // have been ["b", "a", "z"], silently reverting the push.
    await waitFor(() =>
      expect(reorderInput).toEqual({ inboxThreadIds: ["z", "b", "a"] }),
    );
  });

  it("rolls back a failed reorder and ignores another move while saving", async () => {
    const pending = deferred<{ pinnedThreadIds: string[] }>();
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Pin A", isPinned: true }),
          thread({ id: "b", title: "Pin B", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        reorderPinned: () => pending.promise,
      },
    });

    const cardA = await screen.findByRole("link", { name: "Pin A" });
    fireEvent.keyDown(cardA, { key: "ArrowDown", altKey: true });
    await waitFor(() =>
      expect(rendered.rpcCalls.filter((call) => call.method === "reorderPinned"))
        .toHaveLength(1),
    );
    const pinned = screen.getByRole("region", { name: "Pinned" });
    expect(within(pinned).getAllByRole("listitem")[0]!.textContent).toContain("Pin B");

    fireEvent.keyDown(cardA, { key: "ArrowDown", altKey: true });
    expect(rendered.rpcCalls.filter((call) => call.method === "reorderPinned"))
      .toHaveLength(1);

    pending.reject(new Error("order conflict"));
    await waitFor(() =>
      expect(toastMocks.error).toHaveBeenCalledWith(
        "Could not reorder pinned thread",
        { description: "order conflict" },
      ),
    );
    expect(within(pinned).getAllByRole("listitem")[0]!.textContent).toContain("Pin A");
  });

  it("applies the plugin's durable order to inbox threads", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Inbox A", createdAt: 2 }),
          thread({ id: "b", title: "Inbox B", createdAt: 1 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        listInboxOrder: () => ({ inboxThreadIds: ["b", "a"] }),
      },
    });

    await waitFor(() =>
      expect(screen.getAllByRole("listitem")[0]!.textContent).toContain(
        "Inbox B",
      ),
    );
  });

  it.each(["Active", "Inactive"])(
    "keeps %s order on remount while the saved order reloads",
    async (shelf) => {
      const sidebarThreads = {
        status: "ready" as const,
        threads: [
          thread({ id: "a", title: "Inbox A", createdAt: 2 }),
          thread({ id: "b", title: "Inbox B", createdAt: 1 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      };
      const settings = { ...defaultSidebarSettings, inactiveThreadsEnabled: shelf === "Inactive" };
      const first = renderSlot(inbox, listProps, {
        sidebarThreads,
        rpc: {
          getSidebarSettings: () => settings,
          listLifecycle: () => ({ rows: [] }),
          listInboxOrder: () => ({ inboxThreadIds: ["b", "a"] }),
        },
      });
      await screen.findByRole("region", { name: shelf });
      if (shelf === "Inactive") {
        fireEvent.click(within(screen.getByRole("region", { name: shelf })).getByRole("button", { expanded: false }));
      }
      const titles = () => within(screen.getByRole("region", { name: shelf }))
        .getAllByRole("listitem").map((item) => item.textContent);
      await waitFor(() => expect(titles()[0]).toContain("Inbox B"));
      first.lifecycle.unmount();

      const pending = deferred<{ inboxThreadIds: string[] }>();
      const second = renderSlot(inbox, listProps, {
        sidebarThreads,
        rpc: {
          getSidebarSettings: () => settings,
          listLifecycle: () => ({ rows: [] }),
          listInboxOrder: () => pending.promise,
        },
      });
      // Assert the first render, before any RPC can restore the saved order.
      expect(titles()[0]).toContain("Inbox B");
      await act(async () => pending.reject(new Error("temporarily offline")));
      expect(titles()[0]).toContain("Inbox B");
      second.lifecycle.unmount();
    },
  );

  it("uses saved disabled inactivity even when the legacy setting is enabled", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: { status: "ready", threads: [thread()], projects: [] },
      settings: { inactiveThreadsEnabled: true, inactiveAfterHours: "6" },
      rpc: {
        getSidebarSettings: () => ({ ...defaultSidebarSettings, inactiveThreadsEnabled: false }),
        listLifecycle: () => ({ rows: [] }),
      },
    });
    await waitFor(() => expect(screen.queryByRole("region", { name: "Inactive" })).toBeNull());
    expect(screen.getByRole("link", { name: "A thread" })).toBeDefined();
  });

  it("reorders inbox threads with the keyboard and persists the full order", async () => {
    let reorderInput: unknown = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Inbox A", createdAt: 2 }),
          thread({ id: "b", title: "Inbox B", createdAt: 1 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        listInboxOrder: () => ({ inboxThreadIds: ["a", "b"] }),
        reorderInbox: (input) => {
          reorderInput = input;
          return { inboxThreadIds: ["b", "a"] };
        },
      },
    });

    fireEvent.keyDown(
      await screen.findByRole("link", { name: "Inbox B" }),
      { key: "ArrowUp", altKey: true },
    );
    await waitFor(() =>
      expect(reorderInput).toEqual({ inboxThreadIds: ["b", "a"] }),
    );
    expect(screen.getAllByRole("listitem")[0]!.textContent).toContain(
      "Inbox B",
    );
    expect(JSON.parse(localStorage.getItem("bb-sidebar:inbox-order-cache:v1")!)).toEqual(["b", "a"]);
  });

  it("does not let a stale order refresh overwrite a successful reorder", async () => {
    const staleRead = deferred<{ inboxThreadIds: string[] }>();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Inbox A", createdAt: 2 }),
          thread({ id: "b", title: "Inbox B", createdAt: 1 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        listInboxOrder: () => staleRead.promise,
        reorderInbox: () => ({ inboxThreadIds: ["b", "a"] }),
      },
    });

    fireEvent.keyDown(screen.getByRole("link", { name: "Inbox B" }), {
      key: "ArrowUp",
      altKey: true,
    });
    await waitFor(() =>
      expect(screen.getAllByRole("listitem")[0]!.textContent).toContain(
        "Inbox B",
      ),
    );

    await act(async () => staleRead.resolve({ inboxThreadIds: ["a", "b"] }));
    expect(JSON.parse(localStorage.getItem("bb-sidebar:inbox-order-cache:v1")!)).toEqual(["b", "a"]);
    expect(screen.getAllByRole("listitem")[0]!.textContent).toContain(
      "Inbox B",
    );
  });

  it("rolls inbox order back when persistence fails", async () => {
    const pending = deferred<{ inboxThreadIds: string[] }>();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "Inbox A", createdAt: 2 }),
          thread({ id: "b", title: "Inbox B", createdAt: 1 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        listInboxOrder: () => ({ inboxThreadIds: ["a", "b"] }),
        reorderInbox: () => pending.promise,
      },
    });

    fireEvent.keyDown(
      await screen.findByRole("link", { name: "Inbox A" }),
      { key: "ArrowDown", altKey: true },
    );
    await waitFor(() =>
      expect(screen.getAllByRole("listitem")[0]!.textContent).toContain(
        "Inbox B",
      ),
    );

    pending.reject(new Error("database busy"));
    await waitFor(() =>
      expect(toastMocks.error).toHaveBeenCalledWith(
        "Could not reorder inbox thread",
        { description: "database busy" },
      ),
    );
    expect(screen.getAllByRole("listitem")[0]!.textContent).toContain(
      "Inbox A",
    );
  });

  it("unpins a pinned row from its hover action", async () => {
    const rendered = render([
      thread({ id: "pin", title: "Pinned work", isPinned: true }),
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Unpin Pinned work" }),
    );
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "setPinned",
        threadId: "pin",
        pinned: false,
      }),
    );
  });

  it.each(["Active", "Settled", "Snoozed", "Parked"])(
    "pins a thread from %s through the lifecycle RPC",
    async (shelf) => {
      const now = Date.now();
      const rendered = renderSlot(inbox, listProps, {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "to-pin", title: "Pin this thread" })],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: shelf === "Active" ? [] : [{
            threadId: "to-pin",
            parkedAt: shelf === "Parked" ? now : null,
            settledAt: shelf === "Settled" ? now : null,
            settledOverride: shelf === "Settled" ? "settled" : null,
            snoozedUntil: shelf === "Snoozed" ? now + 60_000 : null,
            snoozedAt: shelf === "Snoozed" ? now : null,
          }] }),
          pin: () => ({ ok: true }),
        },
      });
      const section = await screen.findByRole("region", { name: shelf });
      if (shelf !== "Active") {
        fireEvent.click(within(section).getByRole("button", { expanded: false }));
      }
      fireEvent.contextMenu(within(section).getByText("Pin this thread"));
      fireEvent.click(within(await screen.findByRole("menu", { name: "Thread actions" }))
        .getByRole("menuitem", { name: "Pin" }));

      await waitFor(() => expect(rendered.rpcCalls).toContainEqual({
        method: "pin", input: { threadId: "to-pin" },
      }));
      expect(rendered.sidebarActionCalls.filter(call => call.method === "setPinned")).toEqual([]);
    },
  );

  it("reports a failed pin and keeps the thread on its shelf", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "to-pin", title: "Still settled" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [{
          threadId: "to-pin", settledAt: Date.now(), settledOverride: "settled",
          snoozedUntil: null, snoozedAt: null,
        }] }),
        pin: () => { throw new Error("pin update failed"); },
      },
    });
    const section = await screen.findByRole("region", { name: "Settled" });
    fireEvent.click(within(section).getByRole("button", { expanded: false }));
    fireEvent.contextMenu(within(section).getByText("Still settled"));
    fireEvent.click(within(await screen.findByRole("menu", { name: "Thread actions" }))
      .getByRole("menuitem", { name: "Pin" }));

    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith("Could not pin thread", {
      description: "pin update failed",
    }));
    expect(within(section).getByText("Still settled")).toBeDefined();
    expect(screen.queryByRole("region", { name: "Pinned" })).toBeNull();
  });

  it("keeps explicit shelf changes visible while the host's pin flag is stale", async () => {
    const now = Date.now();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "auto", title: "Pinned auto", isPinned: true }),
          thread({ id: "manual", title: "Pinned manual", isPinned: true }),
          thread({ id: "snoozed", title: "Pinned snooze", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        evaluateAutoSettle: () => ({ changedThreadIds: [] }),
        listLifecycle: () => ({
          rows: [
            {
              threadId: "auto",
              settledAt: now,
              settledOverride: null,
              snoozedUntil: null,
              snoozedAt: null,
            },
            {
              threadId: "manual",
              settledAt: now,
              settledOverride: "settled" as const,
              snoozedUntil: null,
              snoozedAt: null,
            },
            {
              threadId: "snoozed",
              settledAt: null,
              settledOverride: null,
              snoozedUntil: now + 60_000,
              snoozedAt: now,
            },
          ],
        }),
      },
    });

    const pinned = await screen.findByRole("region", { name: "Pinned" });
    expect(within(pinned).getByText("Pinned auto")).toBeDefined();
    expect(within(pinned).queryByText("Pinned manual")).toBeNull();
    expect(within(pinned).queryByText("Pinned snooze")).toBeNull();
    expect(
      await screen.findByRole("region", { name: "Settled" }),
    ).toBeDefined();
    expect(
      await screen.findByRole("region", { name: "Snoozed" }),
    ).toBeDefined();
  });

  // The host owns the search field; the plugin only filters by what it is
  // handed, so there is deliberately no second search box to type into.
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
    expect(screen.getAllByRole("option")).toHaveLength(1);
    expect(screen.getByText("Sidebar work")).toBeDefined();
  });

  it("includes matching child threads in search results", () => {
    renderSlot(
      inbox,
      { ...listProps, searchQuery: "needle" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "parent", title: "Parent" }),
            thread({
              id: "child",
              title: "Needle child",
              parentThreadId: "parent",
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const results = screen.getByRole("listbox", {
      name: "Thread search results",
    });
    expect(within(results).getByText("Needle child")).toBeDefined();
  });

  it("shows matching threads from every shelf in one flat result list", async () => {
    const rendered = renderSlot(
      inbox,
      { ...listProps, searchQuery: "match" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "pin", title: "Pinned match", isPinned: true }),
            thread({ id: "active", title: "Active match" }),
            thread({ id: "snoozed", title: "Snoozed match" }),
            thread({ id: "settled", title: "Settled match" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({
            rows: [
              {
                threadId: "snoozed",
                settledAt: null,
                snoozedUntil: Date.now() + 3_600_000,
                snoozedAt: Date.now(),
              },
              {
                threadId: "settled",
                settledAt: Date.now(),
                snoozedUntil: null,
                snoozedAt: null,
              },
            ],
          }),
        },
      },
    );

    await waitFor(() =>
      expect(
        rendered.inspection.rpcCalls.some(
          (call) => call.method === "listLifecycle",
        ),
      ).toBe(true),
    );
    await waitFor(() => expect(screen.getAllByRole("option")).toHaveLength(4));

    const results = screen.getByRole("listbox", {
      name: "Thread search results",
    });
    expect(within(results).getByText("Snoozed match")).toBeDefined();
    expect(within(results).getByText("Settled match")).toBeDefined();
    expect(screen.queryByRole("region", { name: "Snoozed" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Settled" })).toBeNull();
  });

  // A plain search row puts the title, the project and the status on one line.
  // A fixed 112px project column left the title about six characters at a
  // 280px sidebar, so the project yields first: the title is what was searched
  // for. The woke row keeps its own two-row grid instead.
  it("caps the project proportionally on a single-line search row", async () => {
    renderSlot(
      inbox,
      { ...listProps, searchQuery: "match" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "plain", title: "Match plain" })],
          projects: [
            { id: "proj_1", name: "A very long project name", isPersonal: false },
          ],
        },
      },
    );

    const result = await screen.findByRole("option", { name: /Match plain/ });
    const project = within(result).getByText("A very long project name")
      .parentElement!;
    expect(project.className).toContain("max-w-[30%]");
    expect(project.className.split(" ")).not.toContain("max-w-28");
  });

  it("keeps Woke beside pending, failed, running, and idle states in search", async () => {
    const acknowledged: string[] = [];
    let navigated = 0;
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ search_runtime: now - 5 * 60_000 }),
    );
    const threads = [
      thread({
        id: "search_pending",
        title: "Match pending",
        indicator: "waiting-for-input",
        hasPendingInteraction: true,
      }),
      thread({
        id: "search_failed",
        title: "Match failed",
        indicator: "unread-error",
      }),
      thread({
        id: "search_runtime",
        title: "Match runtime",
        indicator: "runtime",
      }),
      thread({
        id: "search_idle",
        title: "Match idle",
        updatedAt: now - 31 * 60_000,
      }),
    ];

    const rendered = renderSlot(
      inbox,
      {
        ...listProps,
        searchQuery: "match",
        onNavigate: () => (navigated += 1),
      },
      {
        sidebarThreads: {
          status: "ready",
          threads,
          projects: [{ id: "proj_1", name: "A very long project name", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({
            rows: threads.map((candidate) => ({
              threadId: candidate.id,
              settledAt: null,
              snoozedUntil:
                candidate.id === "search_pending" ? now + 60_000 : now - 1,
              snoozedAt: now - 60_000,
            })),
          }),
          acknowledgeWake: (input) => {
            acknowledged.push((input as { threadId: string }).threadId);
            return { ok: true };
          },
        },
      },
    );

    const expected = [
      ["Match pending", "Needs you"],
      ["Match failed", "Failed"],
      ["Match runtime", "Working · 5m"],
      ["Match idle", "31m"],
    ] as const;
    await waitFor(() => expect(screen.getAllByRole("option")).toHaveLength(4));
    for (const [title, status] of expected) {
      const result = screen.getByRole("option", { name: new RegExp(title) });
      expect(within(result).getByText("Woke")).toBeDefined();
      expect(within(result).getByText(status)).toBeDefined();
      expect(within(result).queryByRole("button")).toBeNull();
    }

    fireEvent.click(screen.getByRole("option", { name: /Match runtime/ }));
    await waitFor(() => expect(acknowledged).toEqual(["search_runtime"]));
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "search_runtime",
      options: { split: false },
    });
    expect(navigated).toBe(1);
  });

  // The woke row is a two-row grid instead of a flex line, so the roving
  // listbox has to keep working across a mix of the two shapes.
  it("moves through woke and plain search results with the keyboard", async () => {
    const acknowledged: string[] = [];
    let navigated = 0;
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    const rendered = renderSlot(
      inbox,
      {
        ...listProps,
        searchQuery: "match",
        onNavigate: () => (navigated += 1),
      },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({
              id: "woke_match",
              title: "Woke match",
              indicator: "unread-error",
              indicatorLabel: "Unread thread failed",
              updatedAt: now,
            }),
            thread({
              id: "plain_match",
              title: "Plain match",
              updatedAt: now - 31 * 60_000,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({
            rows: [
              {
                threadId: "woke_match",
                settledAt: null,
                snoozedUntil: now - 1,
                snoozedAt: now - 60_000,
              },
            ],
          }),
          acknowledgeWake: (input) => {
            acknowledged.push((input as { threadId: string }).threadId);
            return { ok: true };
          },
        },
      },
    );

    await waitFor(() => expect(screen.getAllByRole("option")).toHaveLength(2));
    const options = screen.getAllByRole("option");
    const woke = options.find(
      (option) => within(option).queryByText("Woke") !== null,
    )!;
    const plain = options.find((option) => option !== woke)!;
    // Woke, the real status, and the project all keep their place on the row.
    expect(within(woke).getByText("Failed")).toBeDefined();
    expect(within(woke).getByText("bb")).toBeDefined();
    expect(within(plain).getByText("31m")).toBeDefined();
    expect(within(plain).queryByText("Woke")).toBeNull();
    // Woke is text in search, not a control: an option must not nest one.
    expect(within(woke).queryByRole("button")).toBeNull();
    expect(nestedInteractiveControls(woke)).toEqual([]);

    const next = options[(options.indexOf(woke) + 1) % options.length]!;
    woke.focus();
    fireEvent.keyDown(woke, { key: "ArrowDown" });
    expect(document.activeElement).toBe(next);
    fireEvent.keyDown(next, { key: "ArrowUp" });
    expect(document.activeElement).toBe(woke);
    expect(woke.tabIndex).toBe(0);
    expect(plain.tabIndex).toBe(-1);

    fireEvent.keyDown(woke, { key: "Enter" });
    await waitFor(() => expect(acknowledged).toEqual(["woke_match"]));
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "woke_match",
      options: { split: false },
    });
    expect(navigated).toBe(1);
  });

  // The woke grid moves the project name to its own row. Without a project
  // there is nothing to move, and the accessible name stays the bare title.
  it("keeps Woke and the status on a search result with no project", async () => {
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    renderSlot(
      inbox,
      { ...listProps, searchQuery: "match" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({
              id: "orphan_match",
              title: "Orphan match",
              projectId: "proj_unknown",
              indicator: "unread-success",
              indicatorLabel: "Unread thread succeeded",
              updatedAt: now,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({
            rows: [
              {
                threadId: "orphan_match",
                settledAt: null,
                snoozedUntil: now - 1,
                snoozedAt: now - 60_000,
              },
            ],
          }),
        },
      },
    );

    const result = await screen.findByRole("option", { name: "Orphan match" });
    expect(within(result).getByText("Woke")).toBeDefined();
    expect(within(result).getByText("Unread")).toBeDefined();
  });

  // The slot renders one status, and a raised hand outranks the runtime bb
  // still reports for the same thread.
  it("prefers a pending question to a running indicator in search results", async () => {
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ asking_match: now - 5 * 60_000 }),
    );
    renderSlot(
      inbox,
      { ...listProps, searchQuery: "match" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({
              id: "asking_match",
              title: "Asking match",
              hasPendingInteraction: true,
              indicator: "runtime",
              indicatorLabel: "Agent is working",
              updatedAt: now,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const result = await screen.findByRole("option", { name: /Asking match/ });
    expect(within(result).getByText("Needs you")).toBeDefined();
    expect(within(result).queryByText(/^Working/)).toBeNull();
    // The runtime's own label must not outlive the status it was replaced by.
    expect(within(result).getByLabelText("Needs you")).toBeDefined();
    expect(within(result).queryByLabelText("Agent is working")).toBeNull();
  });

  it("keeps project scope active while searching", async () => {
    renderSlot(
      inbox,
      { ...listProps, searchQuery: "match" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "a", title: "First match", projectId: "proj_1" }),
            thread({ id: "b", title: "Second match", projectId: "proj_2" }),
          ],
          projects: [
            { id: "proj_1", name: "bb", isPersonal: false },
            { id: "proj_2", name: "other", isPersonal: false },
          ],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    fireEvent.keyDown(screen.getByLabelText(/Project scope/), { key: "Enter" });
    fireEvent.click(screen.getByRole("option", { name: "other" }));
    await waitFor(() =>
      expect(
        screen.getAllByRole("option", { name: /Second match/ }),
      ).toHaveLength(1),
    );
    expect(screen.queryByText("First match")).toBeNull();
  });

  it("filters the project scope card from its search row", async () => {
    renderSlot(
      inbox,
      listProps,
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "a", title: "Sidebar thread", projectId: "proj_1" }),
            thread({ id: "b", title: "Board thread", projectId: "proj_2" }),
          ],
          projects: [
            { id: "proj_1", name: "bb-sidebar", isPersonal: false },
            { id: "proj_2", name: "kanban", isPersonal: false },
          ],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    fireEvent.keyDown(screen.getByLabelText(/Project scope/), { key: "Enter" });
    // The card opens with the caret already in the search row.
    await waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByLabelText("Filter projects"),
      ),
    );
    const projectList = screen.getByRole("listbox", { name: "Projects" });
    expect(within(projectList).getAllByRole("option")).toHaveLength(3);

    fireEvent.change(screen.getByLabelText("Filter projects"), {
      target: { value: "KAN" },
    });
    expect(
      within(projectList)
        .getAllByRole("option")
        .map((option) => option.textContent),
    ).toEqual(["kanban"]);

    // Enter takes the highlighted row, which filtering moved to the top.
    fireEvent.keyDown(screen.getByLabelText("Filter projects"), {
      key: "Enter",
    });
    await waitFor(() =>
      expect(screen.getByLabelText(/Project scope: kanban/)).toBeDefined(),
    );
    expect(screen.getByText("Board thread")).toBeDefined();
    expect(screen.queryByText("Sidebar thread")).toBeNull();
  });

  it("says so when no project matches the scope search", () => {
    render([thread({ title: "Sidebar thread" })]);

    fireEvent.keyDown(screen.getByLabelText(/Project scope/), { key: "Enter" });
    fireEvent.change(screen.getByLabelText("Filter projects"), {
      target: { value: "nope" },
    });
    expect(
      within(screen.getByRole("listbox", { name: "Projects" })).queryAllByRole(
        "option",
      ),
    ).toHaveLength(0);
    expect(screen.getByText("No projects found")).toBeDefined();
  });

  it("moves through results with arrows and opens the highlighted row", async () => {
    let navigated = 0;
    const rendered = renderSlot(
      inbox,
      {
        ...listProps,
        searchQuery: "thread",
        onNavigate: () => (navigated += 1),
      },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "newer", title: "Newer thread", createdAt: 2 }),
            thread({ id: "older", title: "Older thread", createdAt: 1 }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const results = await screen.findAllByRole("option");
    results[0]!.focus();
    fireEvent.keyDown(results[0]!, { key: "ArrowDown" });
    expect(document.activeElement).toBe(results[1]);
    expect(results[1]!.tabIndex).toBe(0);

    fireEvent.keyDown(results[1]!, { key: "Enter" });
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "older",
      options: { split: false },
    });
    expect(navigated).toBe(1);
  });

  it("asks the host to clear search when Escape is pressed in results", async () => {
    let cleared = 0;
    renderSlot(
      inbox,
      {
        ...listProps,
        searchQuery: "thread",
        onNavigate: () => (cleared += 1),
      },
      {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ title: "A thread" })],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: { listLifecycle: () => ({ rows: [] }) },
      },
    );

    const result = await screen.findByRole("option");
    result.focus();
    fireEvent.keyDown(result, { key: "Escape" });
    expect(cleared).toBe(1);
  });

  it("ships no search field of its own", () => {
    render([thread({ id: "a" })]);
    expect(screen.queryByLabelText("Search threads")).toBeNull();
  });

  it("ships no new-thread button of its own", () => {
    render([thread({ id: "a" })]);
    expect(screen.queryByLabelText("New thread")).toBeNull();
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

  it("invites a break when there are no active threads", () => {
    const view = render([]);
    expect(
      screen.getByText("All clear. Time to touch some grass."),
    ).toBeDefined();
    expect(view.container.querySelector("svg")).not.toBeNull();
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
    expect(
      within(shelf).getByRole("listitem").textContent,
    ).toMatch(/bb\s*·\s*Finished work/);
    expect(
      within(shelf).getByLabelText("bb · Finished work"),
    ).toBeDefined();
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

  it("offers Park thread below the snooze times and allows parking again after Undo", async () => {
    const park = vi.fn(() => ({ ok: true, reclaim: SETTLED_NOTHING }));
    const resume = vi.fn(() => ({ ok: true }));
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_park", title: "Quiet" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }), park, resume },
    });
    // Rendered (not merely accepted as props): a card whose park controls
    // never mount leaves the whole feature unreachable.
    expect(await screen.findByLabelText("Settle thread")).toBeDefined();
    const snooze = screen.getByRole("combobox", { name: "Snooze thread" });
    expect(
      snooze.querySelector('[data-icon="Clock"]'),
    ).not.toBeNull();
    expect(snooze.querySelector('[data-icon="ChevronDown"]')).not.toBeNull();
    expect(snooze.classList.contains("[&>svg:last-child]:hidden")).toBe(true);
    expect(snooze.classList.contains("w-5")).toBe(true);
    fireEvent.keyDown(snooze, { key: "Enter" });
    expect(
      await screen.findByRole("option", { name: "1 hour" }),
    ).toBeDefined();
    expect(screen.getByRole("option", { name: "Wait refresh (5 hours)" })).toBeDefined();
    expect(screen.getByRole("option", { name: "This evening" })).toBeDefined();
    expect(screen.getByRole("option", { name: "Next week" })).toBeDefined();
    const menu = screen.getByRole("listbox");
    const parkOption = within(menu).getByRole("option", { name: "Park thread" });
    expect(within(menu).getAllByRole("option").at(-1)).toBe(parkOption);
    fireEvent.click(parkOption);
    await waitFor(() => expect(park).toHaveBeenCalledTimes(1));
    expect(rendered.rpcCalls).toContainEqual({ method: "park", input: { threadId: "thr_park" } });
    expect(rendered.rpcCalls.some(call => call.method === "snooze" || call.method === "settle")).toBe(false);

    await waitFor(() => expect(toastMocks.success).toHaveBeenCalled());
    const undo = toastMocks.success.mock.calls.find(([message]) => message === "Thread parked")![1].action;
    act(() => undo.onClick());
    await waitFor(() => expect(resume).toHaveBeenCalledTimes(1));
    fireEvent.keyDown(snooze, { key: "Enter" });
    fireEvent.click(await screen.findByRole("option", { name: "Park thread" }));
    await waitFor(() => expect(park).toHaveBeenCalledTimes(2));
  });

  it("keeps status rows actionable through snooze, settle, and unpin controls", async () => {
    const snooze = vi.fn(() => ({ ok: true }));
    const settle = vi.fn(() => ({ ok: true, reclaim: SETTLED_NOTHING }));
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "thr_failed",
            title: "Failed work",
            indicator: "unread-error",
            indicatorLabel: "Failed",
            isPinned: true,
          }),
          thread({
            id: "thr_unread",
            title: "Unread work",
            indicator: "unread-success",
            indicatorLabel: "Unread",
          }),
          thread({
            id: "thr_idle",
            title: "Idle work",
            updatedAt: Date.now() - 2 * 60_000,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }), snooze, settle },
    });

    expect(await screen.findByText("Failed")).toBeDefined();
    expect(screen.getByText("Unread")).toBeDefined();
    expect(screen.getByText(/^\d+m$/)).toBeDefined();

    fireEvent.click(screen.getByRole("button", { name: "Unpin Failed work" }));
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "setPinned",
        threadId: "thr_failed",
        pinned: false,
      }),
    );

    const unreadRow = screen.getByText("Unread work").closest("li")!;
    fireEvent.click(
      within(unreadRow).getByRole("button", { name: "Settle thread" }),
    );
    await waitFor(() =>
      expect(settle).toHaveBeenCalledWith({ threadId: "thr_unread" }),
    );

    const idleRow = screen.getByText("Idle work").closest("li")!;
    fireEvent.keyDown(
      within(idleRow).getByRole("combobox", { name: "Snooze thread" }),
      { key: "Enter" },
    );
    fireEvent.click(await screen.findByRole("option", { name: "1 hour" }));
    await waitFor(() =>
      expect(snooze).toHaveBeenCalledWith({
        threadId: "thr_idle",
        snoozedUntil: expect.any(Number),
      }),
    );
  });

  // jsdom cannot evaluate `@media (hover: none)`, so the regression this
  // guards — a touch layout that faded the status out behind the park actions
  // — only shows in the class contract. The structural half is asserted too:
  // status and actions are rendered together, and neither is hidden.
  it("keeps the status beside the touch park actions instead of fading it out", async () => {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    const parkable = [
      ["Touch failed", "unread-error", "Failed"],
      ["Touch unread", "unread-success", "Unread"],
      // A question bb reports without a pending interaction is still parkable.
      ["Touch asked", "waiting-for-input", "Needs you"],
      ["Touch idle", "none", "4m"],
    ] as const;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: parkable.map(([title, indicator]) =>
          thread({
            id: title,
            title,
            indicator,
            updatedAt: minute - 4 * 60_000,
          }),
        ),
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    await screen.findByText("Touch failed");
    for (const [title, , statusText] of parkable) {
      const row = screen.getByText(title).closest("li")!;
      // The actions the touch layout has to sit beside, not on top of.
      expect(
        within(row).getByRole("combobox", { name: "Snooze thread" }),
      ).toBeDefined();
      expect(
        within(row).getByRole("button", { name: "Settle thread" }),
      ).toBeDefined();
      // The card's anchor is a sibling of the controls, not their ancestor.
      expect(nestedInteractiveControls(row)).toEqual([]);

      const { status, statusWrapper, slot, actions } = statusSlotParts(
        row,
        statusText,
      );
      expect(actions).not.toBe(statusWrapper);
      expect(status.getAttribute("aria-hidden")).toBeNull();
      expect(status.hasAttribute("hidden")).toBe(false);
      expect(statusWrapper.getAttribute("aria-hidden")).toBeNull();
      // Touch: both spans return to the flow at full opacity, and the slot
      // widens so they sit side by side instead of stacked.
      for (const className of [
        "[@media(hover:none)]:static",
        "[@media(hover:none)]:opacity-100",
      ]) {
        expect(statusWrapper.className).toContain(className);
        expect(actions.className).toContain(className);
      }
      expect(slot.className).toContain("[@media(hover:none)]:w-auto");
      expect(slot.className).toContain("[@media(hover:none)]:gap-1.5");
      expect(statusWrapper.className).not.toContain(
        "[@media(hover:none)]:opacity-0",
      );
      // A hover device still trades the status for the actions.
      expect(statusWrapper.className).toContain(
        "[@media(hover:hover)]:group-hover/card:opacity-0",
      );
    }
  });

  // Opening the snooze menu pins the actions open on a hover device by hiding
  // the status. On touch the two already share the row, so the status stays.
  it("keeps the touch status visible while the snooze menu is open", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "thr_open", title: "Menu open", indicator: "unread-error" }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    const row = (await screen.findByText("Menu open")).closest("li")!;
    fireEvent.keyDown(
      within(row).getByRole("combobox", { name: "Snooze thread" }),
      { key: "Enter" },
    );
    await screen.findByRole("option", { name: "1 hour" });

    const { statusWrapper } = statusSlotParts(row, "Failed");
    expect(within(row).getByText("Failed")).toBeDefined();
    expect(statusWrapper.className).toContain("opacity-0");
    expect(statusWrapper.className).toContain(
      "[@media(hover:none)]:opacity-100",
    );
  });

  // A working or blocked thread cannot be parked, so it has no actions to
  // share the slot with — but it must still show its status on touch.
  it("keeps the status on rows that offer no park actions", async () => {
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ thr_working: now - 5 * 60_000 }),
    );
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "thr_working",
            title: "Still working",
            indicator: "runtime",
            indicatorLabel: "Agent is working",
            updatedAt: now,
          }),
          thread({
            id: "thr_pending",
            title: "Still asking",
            hasPendingInteraction: true,
            indicator: "waiting-for-input",
            updatedAt: now,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }) },
    });

    await screen.findByText("Still working");
    for (const [title, statusText] of [
      ["Still working", "Working · 5m"],
      ["Still asking", "Needs you"],
    ] as const) {
      const row = screen.getByText(title).closest("li")!;
      expect(
        within(row).queryByRole("combobox", { name: "Snooze thread" }),
      ).toBeNull();
      expect(
        within(row).queryByRole("button", { name: "Settle thread" }),
      ).toBeNull();
      const { status, statusWrapper, slot } = statusSlotParts(row, statusText);
      expect(status.getAttribute("aria-hidden")).toBeNull();
      expect(statusWrapper.className).not.toContain("opacity-0");
      // Intrinsic width with a floor: nothing is layered over the status.
      expect(slot.className).toContain("w-auto");
      expect(slot.className).toContain("min-w-20");
    }
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
          return { ok: true, reclaim: SETTLED_NOTHING };
        },
      },
    });
    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() => expect(settled).toBe("thr_park"));
  });

  // A raised hand outranks a reported runtime in the slot, and it also
  // outranks any stored shelf: the row stays on Active with no park controls.
  it("prefers a pending question to a running indicator on a parent card", async () => {
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ thr_ask: now - 5 * 60_000 }),
    );
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "thr_ask",
            title: "Asking while working",
            hasPendingInteraction: true,
            indicator: "runtime",
            indicatorLabel: "Agent is working",
            updatedAt: now,
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      // Settled in the store, but a raised hand brings it straight back.
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_ask",
              settledAt: 200,
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });

    const active = screen.getByRole("region", { name: "Active" });
    const row = (
      await within(active).findByText("Asking while working")
    ).closest("li")!;
    expect(within(row).getByText("Needs you")).toBeDefined();
    expect(within(row).queryByText(/^Working/)).toBeNull();
    expect(within(row).getByLabelText("Needs you")).toBeDefined();
    expect(within(row).queryByLabelText("Agent is working")).toBeNull();
    expect(screen.queryByRole("region", { name: "Settled" })).toBeNull();
  });

  // Parked rows share the status vocabulary: a settled thread that failed
  // says so rather than falling back to its age.
  it("shows a settled row's status instead of its age", async () => {
    const now = Date.now();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({
            id: "thr_settled",
            title: "Settled failure",
            indicator: "unread-error",
            indicatorLabel: "Unread thread failed",
            updatedAt: now - (3 * 3_600_000 + 60_000),
            createdAt: now - (3 * 3_600_000 + 60_000),
            latestAttentionAt: now - (3 * 3_600_000 + 60_000),
          }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_settled",
              settledAt: now,
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });

    const shelf = await screen.findByRole("region", { name: "Settled" });
    fireEvent.click(within(shelf).getByRole("button"));
    const row = within(shelf).getByText("Settled failure").closest("li")!;
    expect(within(row).getByText("Failed").className).toContain(
      "text-[color:var(--bb-sidebar-tone-error)]",
    );
    expect(within(row).queryByText("3h")).toBeNull();
    expect(
      within(row).getByRole("button", { name: "Un-settle thread" }),
    ).toBeDefined();
  });

  it("keeps the last usable view when lifecycle refresh fails", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_available", title: "Still available" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => Promise.reject(new Error("backend reloading")),
      },
    });

    expect(screen.getByText("Still available")).toBeDefined();
    await waitFor(() => expect(screen.getByText("Still available")).toBeDefined());
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
    expect(within(shelf).getByLabelText("bb · Later")).toBeDefined();
    expect(within(shelf).getByText("bb").className).toContain(
      "text-muted-foreground/50",
    );
    expect(within(shelf).getByText("·").className).toContain("text-sm");
    expect(within(shelf).getByText("Later").className).toContain(
      "text-foreground/80",
    );
    expect(within(shelf).getByLabelText("Wake thread now")).toBeDefined();
  });

  it("persists each shelf's expanded state across remounts", async () => {
    const now = Date.now();
    const rows = [
      {
        threadId: "thr_done",
        settledAt: 200,
        snoozedUntil: null,
        snoozedAt: null,
      },
      {
        threadId: "thr_later",
        settledAt: null,
        snoozedUntil: now + 60_000,
        snoozedAt: now,
      },
    ];
    const options = {
      sidebarThreads: {
        status: "ready" as const,
        threads: [
          thread({ id: "thr_active", title: "Active work", updatedAt: now }),
          thread({
            id: "thr_inactive",
            title: "Inactive work",
            updatedAt: now - 7 * 60 * 60 * 1_000,
          }),
          thread({ id: "thr_done", title: "Finished work" }),
          thread({ id: "thr_later", title: "Later work" }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: {
        inactiveThreadsEnabled: true,
        inactiveAfterHours: "6",
      },
      rpc: { listLifecycle: () => ({ rows }) },
    };

    renderSlot(inbox, listProps, options);
    let activeShelf = screen.getByRole("region", { name: "Active" });
    let inactiveShelf = screen.getByRole("region", { name: "Inactive" });
    let settledShelf = await screen.findByRole("region", { name: "Settled" });
    let snoozedShelf = await screen.findByRole("region", { name: "Snoozed" });
    fireEvent.click(
      within(activeShelf).getByRole("button", { expanded: true }),
    );
    fireEvent.click(within(inactiveShelf).getByRole("button"));
    fireEvent.click(within(settledShelf).getByRole("button"));
    fireEvent.click(within(snoozedShelf).getByRole("button"));
    expect(within(activeShelf).queryByText("Active work")).toBeNull();
    expect(within(inactiveShelf).getByText("Inactive work")).toBeDefined();
    expect(within(settledShelf).getByText("Finished work")).toBeDefined();
    expect(within(snoozedShelf).getByText("Later work")).toBeDefined();

    cleanup();
    renderSlot(inbox, listProps, options);
    activeShelf = screen.getByRole("region", { name: "Active" });
    inactiveShelf = screen.getByRole("region", { name: "Inactive" });
    settledShelf = await screen.findByRole("region", { name: "Settled" });
    snoozedShelf = await screen.findByRole("region", { name: "Snoozed" });
    expect(
      within(activeShelf).getByRole("button", { expanded: false }),
    ).toBeDefined();
    expect(
      within(inactiveShelf).getByRole("button", { expanded: true }),
    ).toBeDefined();
    expect(
      within(settledShelf).getByRole("button", { expanded: true }),
    ).toBeDefined();
    expect(
      within(snoozedShelf).getByRole("button", { expanded: true }),
    ).toBeDefined();
    expect(within(activeShelf).queryByText("Active work")).toBeNull();
    expect(within(inactiveShelf).getByText("Inactive work")).toBeDefined();
    expect(within(settledShelf).getByText("Finished work")).toBeDefined();
    expect(within(snoozedShelf).getByText("Later work")).toBeDefined();
  });

  it("does not flash inactive and parked threads as Active after an app restart", async () => {
    const now = Date.now();
    const pendingSettings = deferred<typeof defaultSidebarSettings>();
    const pendingLifecycle = deferred<{
      rows: Array<{
        threadId: string;
        settledAt: number;
        snoozedUntil: null;
        snoozedAt: null;
      }>;
    }>();
    const props = { ...listProps };
    const sidebarThreads = {
      status: "ready" as const,
      threads: [
        thread({
          id: "inactive",
          title: "Inactive work",
          updatedAt: now - 7 * 60 * 60 * 1_000,
        }),
        thread({ id: "settled", title: "Settled work" }),
      ],
      projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
    };
    renderSlot(inbox, props, {
      sidebarThreads,
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        listLifecycle: () => ({
          rows: [
            {
              threadId: "settled",
              settledAt: now,
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });

    await screen.findByRole("region", { name: "Inactive" });
    await screen.findByRole("region", { name: "Settled" });
    cleanup();

    renderSlot(inbox, props, {
      sidebarThreads,
      rpc: {
        getSidebarSettings: () => pendingSettings.promise,
        listLifecycle: () => pendingLifecycle.promise,
      },
    });

    const inactiveShelf = screen.getByRole("region", { name: "Inactive" });
    const settledShelf = screen.getByRole("region", { name: "Settled" });
    expect(
      within(inactiveShelf).getByRole("button", { expanded: false }),
    ).toBeDefined();
    expect(
      within(settledShelf).getByRole("button", { expanded: false }),
    ).toBeDefined();
    expect(screen.queryByRole("region", { name: "Active" })).toBeNull();
    expect(screen.queryByText("Inactive work")).toBeNull();
    expect(screen.queryByText("Settled work")).toBeNull();
  });

  it("keeps the currently open parked row visible while collapsed", async () => {
    renderSlot(inbox, { ...listProps, activeThreadId: "thr_open" }, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_open", title: "Open but settled" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "thr_open",
              settledAt: 200,
              snoozedUntil: null,
              snoozedAt: null,
            },
          ],
        }),
      },
    });

    const shelf = await screen.findByRole("region", { name: "Settled" });
    expect(
      within(shelf).getByRole("button", { expanded: false }),
    ).toBeDefined();
    expect(within(shelf).getByText("Open but settled")).toBeDefined();
  });

  it("sorts snoozed rows by soonest wake and settled rows by settle time", async () => {
    const now = Date.now();
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "later", title: "Later wake", createdAt: 100 }),
          thread({ id: "sooner", title: "Sooner wake", createdAt: 1 }),
          thread({ id: "old-settle", title: "Older settle", createdAt: 999 }),
          thread({ id: "new-settle", title: "Newer settle", createdAt: 1 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            { threadId: "later", settledAt: null, snoozedUntil: now + 5_000, snoozedAt: now },
            { threadId: "sooner", settledAt: null, snoozedUntil: now + 1_000, snoozedAt: now },
            { threadId: "old-settle", settledAt: 500, snoozedUntil: null, snoozedAt: null },
            { threadId: "new-settle", settledAt: 900, snoozedUntil: null, snoozedAt: null },
          ],
        }),
      },
    });

    const snoozedShelf = await screen.findByRole("region", { name: "Snoozed" });
    const settledShelf = await screen.findByRole("region", { name: "Settled" });
    fireEvent.click(within(snoozedShelf).getByRole("button"));
    fireEvent.click(within(settledShelf).getByRole("button"));
    expect(
      within(snoozedShelf).getAllByRole("listitem").map((row) => row.textContent),
    ).toEqual([expect.stringContaining("Sooner wake"), expect.stringContaining("Later wake")]);
    expect(
      within(settledShelf).getAllByRole("listitem").map((row) => row.textContent),
    ).toEqual([expect.stringContaining("Newer settle"), expect.stringContaining("Older settle")]);
  });

  it("shows 10 settled rows initially and loads 25 more at a time", async () => {
    const threads = Array.from({ length: 36 }, (_, index) =>
      thread({ id: `settled-${index}`, title: `Settled ${index}` }),
    );
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads,
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: threads.map((candidate, index) => ({
            threadId: candidate.id,
            settledAt: 1_000 - index,
            snoozedUntil: null,
            snoozedAt: null,
          })),
        }),
      },
    });

    const shelf = await screen.findByRole("region", { name: "Settled" });
    fireEvent.click(within(shelf).getByRole("button"));
    expect(within(shelf).getAllByRole("listitem")).toHaveLength(10);
    fireEvent.click(within(shelf).getByRole("button", { name: "Load 25 more" }));
    expect(within(shelf).getAllByRole("listitem")).toHaveLength(35);
    fireEvent.click(within(shelf).getByRole("button", { name: "Load 1 more" }));
    expect(within(shelf).getAllByRole("listitem")).toHaveLength(36);
    expect(within(shelf).queryByText(/Load .* more/)).toBeNull();
  });

  it("keeps Woke beside the current card status and preserves its controls", async () => {
    const acknowledged: string[] = [];
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ runtime: now - 5 * 60_000 }),
    );
    const threads = [
      thread({
        id: "pending",
        title: "Pending wake",
        indicator: "waiting-for-input",
        hasPendingInteraction: true,
      }),
      thread({
        id: "failed",
        title: "Failed wake",
        indicator: "unread-error",
        isPinned: true,
      }),
      thread({ id: "runtime", title: "Runtime wake", indicator: "runtime" }),
      thread({
        id: "idle",
        title: "Idle wake",
        updatedAt: now - 31 * 60_000,
      }),
    ];
    let lifecycleRows = threads.map((candidate) => ({
      threadId: candidate.id,
      settledAt: null,
      snoozedUntil: candidate.id === "pending" ? now + 60_000 : now - 1,
      snoozedAt: now - 60_000,
    }));
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads,
        projects: [{ id: "proj_1", name: "A very long project name", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: lifecycleRows }),
        acknowledgeWake: (input) => {
          const threadId = (input as { threadId: string }).threadId;
          acknowledged.push(threadId);
          lifecycleRows = lifecycleRows.filter((row) => row.threadId !== threadId);
          return { ok: true };
        },
      },
    });

    const expected = [
      ["Pending wake", "Needs you"],
      ["Failed wake", "Failed"],
      ["Runtime wake", "Working · 5m"],
      ["Idle wake", "31m"],
    ] as const;
    for (const [title, status] of expected) {
      const row = (await screen.findByText(title)).closest("li")!;
      expect(within(row).getByRole("button", { name: "Dismiss Woke marker" })).toBeDefined();
      expect(within(row).getByText(status)).toBeDefined();
    }

    const pendingRow = screen.getByText("Pending wake").closest("li")!;
    fireEvent.click(within(pendingRow).getByRole("button", { name: "Dismiss Woke marker" }));
    await waitFor(() => expect(acknowledged).toEqual(["pending"]));
    await rendered.emitRealtime("lifecycle", {});
    await waitFor(() =>
      expect(
        within(screen.getByText("Pending wake").closest("li")!).queryByRole(
          "button",
          { name: "Dismiss Woke marker" },
        ),
      ).toBeNull(),
    );
    expect(
      within(screen.getByText("Pending wake").closest("li")!).getByText(
        "Needs you",
      ),
    ).toBeDefined();
    expect(rendered.sidebarActionCalls.some((call) => call.method === "open")).toBe(false);

    const failedRow = screen.getByText("Failed wake").closest("li")!;
    fireEvent.click(within(failedRow).getByRole("button", { name: "Unpin Failed wake" }));
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "setPinned",
        threadId: "failed",
        pinned: false,
      }),
    );
    expect(acknowledged).toEqual(["pending"]);
    expect(within(failedRow).getByText("Failed")).toBeDefined();

    fireEvent.click(within(failedRow).getByRole("link", { name: "Failed wake" }));
    await waitFor(() => expect(acknowledged).toEqual(["pending", "failed"]));
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "failed",
      options: { split: false },
    });
  });
  // Dismissing the marker is a correction, not navigation: the row stays put
  // with its real status, and nothing opens.
  it("dismisses the Woke marker without opening or navigating", async () => {
    const acknowledged: string[] = [];
    let navigated = 0;
    const now = Math.floor(Date.now() / 60_000) * 60_000;
    let lifecycleRows = [
      {
        threadId: "woke",
        settledAt: null,
        snoozedUntil: now - 1,
        snoozedAt: now - 60_000,
      },
    ];
    const rendered = renderSlot(
      inbox,
      { ...listProps, onNavigate: () => (navigated += 1) },
      {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({
              id: "woke",
              title: "Woke work",
              indicator: "unread-error",
              indicatorLabel: "Unread thread failed",
              updatedAt: now,
            }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: lifecycleRows }),
          acknowledgeWake: (input) => {
            acknowledged.push((input as { threadId: string }).threadId);
            lifecycleRows = [];
            return { ok: true };
          },
        },
      },
    );

    const row = (await screen.findByText("Woke work")).closest("li")!;
    const dismiss = within(row).getByRole("button", {
      name: "Dismiss Woke marker",
    });
    expect(within(row).getByText("Failed")).toBeDefined();
    // The card's navigation anchor is a sibling of the controls, never their
    // ancestor, so no control ends up inside another control.
    expect(dismiss.closest("a")).toBeNull();
    expect(nestedInteractiveControls(row)).toEqual([]);

    fireEvent.click(dismiss);
    await waitFor(() => expect(acknowledged).toEqual(["woke"]));
    expect(navigated).toBe(0);
    expect(rendered.sidebarActionCalls).toEqual([]);

    await rendered.emitRealtime("lifecycle", {});
    const settled = () => screen.getByText("Woke work").closest("li")!;
    await waitFor(() =>
      expect(
        within(settled()).queryByRole("button", {
          name: "Dismiss Woke marker",
        }),
      ).toBeNull(),
    );
    expect(within(settled()).getByText("Failed")).toBeDefined();
    expect(navigated).toBe(0);
  });

});

type ParkingAction = "settle" | "snooze" | "park";
const parkingActions: readonly ParkingAction[] = ["settle", "snooze", "park"];

async function parkFromCard(row: HTMLElement, action: ParkingAction) {
  if (action === "settle") {
    fireEvent.click(within(row).getByRole("button", { name: "Settle thread" }));
  } else {
    fireEvent.keyDown(within(row).getByRole("combobox", { name: "Snooze thread" }), { key: "Enter" });
    fireEvent.click(await screen.findByRole("option", {
      name: action === "park" ? "Park thread" : "1 hour",
    }));
  }
}

async function parkFromMenu(row: HTMLElement, action: ParkingAction) {
  fireEvent.contextMenu(row);
  const menu = await screen.findByRole("menu", { name: "Thread actions" });
  if (action === "snooze") {
    fireEvent.click(within(menu).getByText("Snooze"));
    fireEvent.click(await screen.findByRole("menuitem", { name: "1 hour" }));
  } else {
    fireEvent.click(within(menu).getByText(action === "park" ? "Park thread" : "Settle"));
  }
}

describe("row context menu", () => {
  it("offers the plugin's own thread actions on right-click", async () => {
    render([thread({ id: "thr_menu", title: "Right click me" })]);
    const row = await screen.findByText("Right click me");
    fireEvent.contextMenu(row);
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    // The plugin builds this menu itself — the SDK ships no menu component —
    // so the items are this plugin's choice, backed by the action hook.
    expect(
      within(menu)
        .getAllByRole("menuitem")
        .map((item) => item.textContent),
    ).toEqual([
      "Open in split",
      "Parent",
      "Project",
      "Pin",
      "Park thread",
      "Settle",
      "Snooze",
      "Rename",
      "Regenerate title",
      "Mark unread",
      "Copy",
      "Archive",
      "Delete",
    ]);
    expect(within(menu).getAllByRole("separator")).toHaveLength(4);
  });

  describe.each(parkingActions)("%s navigation", (action) => {
    it("updates another thread from the context menu without changing the open thread", async () => {
      let settled: string | null = null;
      const rendered = renderSlot(inbox, { ...listProps, activeThreadId: "open" }, {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "thr_settle", title: "Settle from menu" }),
            thread({ id: "open", title: "Stay here" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          [action]: (input) => {
            settled = (input as { threadId: string }).threadId;
            return { ok: true, reclaim: SETTLED_NOTHING };
          },
        },
      });

      await parkFromMenu(await screen.findByText("Settle from menu"), action);
      await waitFor(() => expect(settled).toBe("thr_settle"));
      await waitFor(() => expect(toastMocks.success).toHaveBeenCalled());
      expect(rendered.sidebarActionCalls).toEqual([]);
    });

    it("opens the next Active thread when leaving its first row", async () => {
      let navigated = 0;
      const rendered = renderSlot(
        inbox,
        {
          ...listProps,
          activeThreadId: "current",
          onNavigate: () => (navigated += 1),
        },
        {
          sidebarThreads: {
            status: "ready",
            threads: [
              thread({ id: "current", title: "Current", createdAt: 20 }),
              thread({ id: "next", title: "Next", createdAt: 10 }),
            ],
            projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
          },
          rpc: {
            listLifecycle: () => ({ rows: [] }),
            [action]: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
          },
        },
      );

      await parkFromMenu(await screen.findByText("Current"), action);
      await waitFor(() =>
        expect(rendered.sidebarActionCalls).toContainEqual({
          method: "open",
          threadId: "next",
        }),
      );
      expect(navigated).toBe(1);
    });

    it.each([
      ["manual", "manual", false],
      ["manual", "manual", true],
      ["created", "created", true],
      ["activity", "activity", true],
      ["project", "project", true],
    ] as const)("leaving a thread in %s order opens %s first with Active collapsed: %s", async (mode, expectedId, collapsed) => {
      localStorage.setItem("bb-sidebar:active-sort:v1", mode);
      const order = ["manual", "current", "created", "activity", "project"];
      localStorage.setItem("bb-sidebar:inbox-order-cache:v1", JSON.stringify(order));
      const rendered = renderSlot(inbox, { ...listProps, activeThreadId: "current" }, {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "current", title: "Current", createdAt: 50, updatedAt: 50 }),
            thread({ id: "manual", title: "Manual first", createdAt: 20, updatedAt: 20 }),
            thread({ id: "created", title: "Newest first", createdAt: 100, updatedAt: 100 }),
            thread({ id: "activity", title: "Recent first", createdAt: 10, updatedAt: 200 }),
            thread({ id: "project", title: "Alpha first", projectId: "alpha", createdAt: 5 }),
          ],
          projects: [
            { id: "proj_1", name: "Zulu", isPersonal: false },
            { id: "alpha", name: "Alpha", isPersonal: false },
          ],
        },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          listInboxOrder: () => ({ inboxThreadIds: order }),
          [action]: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
        },
      });

      const active = await screen.findByRole("region", { name: "Active" });
      if (collapsed) {
        fireEvent.click(within(active).getByRole("button", { expanded: true }));
      }
      const current = within(active).getByText("Current").closest("li")!;
      await parkFromCard(current, action);
      await waitFor(() => expect(rendered.sidebarActionCalls).toContainEqual({
        method: "open", threadId: expectedId,
      }));
    });

    it.each([
      ["current", "first-pin"],
      ["first-pin", "second-pin"],
    ])("leaving %s selects %s before Active, using the full pinned order", async (currentId, expectedId) => {
      localStorage.setItem("bb-sidebar:active-sort:v1", "created");
      const rendered = renderSlot(inbox, { ...listProps, activeThreadId: currentId }, {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "first-pin", title: "First pin", isPinned: true, createdAt: 10 }),
            thread({ id: "second-pin", title: "Second pin", isPinned: true, createdAt: 100 }),
            thread({ id: "current", title: "Current", createdAt: 20 }),
            thread({ id: "active", title: "First active", createdAt: 200 }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          [action]: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
        },
      });

      const pinned = await screen.findByRole("region", { name: "Pinned" });
      fireEvent.click(within(pinned).getByRole("button", { expanded: true }));
      const current = screen.getByText(currentId === "current" ? "Current" : "First pin").closest("li")!;
      await parkFromCard(current, action);
      await waitFor(() => expect(rendered.sidebarActionCalls).toContainEqual({
        method: "open", threadId: expectedId,
      }));
    });

    it("selects the first Active thread when leaving the last Pinned thread", async () => {
      const rendered = renderSlot(inbox, { ...listProps, activeThreadId: "pinned" }, {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "pinned", title: "Last pin", isPinned: true }),
            thread({ id: "first", title: "First active", createdAt: 20 }),
            thread({ id: "last", title: "Last active", createdAt: 10 }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          [action]: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
        },
      });

      const pinned = await screen.findByRole("region", { name: "Pinned" });
      await parkFromCard(within(pinned).getByText("Last pin").closest("li")!, action);
      await waitFor(() => expect(rendered.sidebarActionCalls).toContainEqual({
        method: "open", threadId: "first",
      }));
    });

    it.each([false, true])("opens a project-scoped composer when Pinned and Active are empty after the action, with the last thread pinned: %s", async (isPinned) => {
      const now = Date.now();
      const rendered = renderSlot(
        inbox,
        { ...listProps, activeThreadId: "only" },
        {
          sidebarThreads: {
            status: "ready",
            threads: [
              thread({ id: "only", title: "Only thread", updatedAt: now, isPinned }),
              thread({ id: "inactive", title: "Inactive thread" }),
              thread({ id: "parked", title: "Parked thread" }),
              thread({ id: "snoozed", title: "Snoozed thread" }),
              thread({ id: "settled", title: "Settled thread" }),
            ],
            projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
          },
          settings: { inactiveThreadsEnabled: true, inactiveAfterHours: "6" },
          rpc: {
            listLifecycle: () => ({ rows: [
              { threadId: "parked", parkedAt: now, settledAt: null, snoozedUntil: null, snoozedAt: null },
              { threadId: "snoozed", settledAt: null, snoozedUntil: now + 60_000, snoozedAt: now },
              { threadId: "settled", settledAt: now, snoozedUntil: null, snoozedAt: null },
            ] }),
            [action]: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
          },
        },
      );

      await screen.findByRole("region", { name: "Settled" });
      const current = screen.getByText("Only thread").closest("li")!;
      await parkFromCard(current, action);
      await waitFor(() =>
        expect(rendered.sidebarActionCalls).toContainEqual({
          method: "openNewThread",
          options: { projectId: "proj_1", focusPrompt: true },
        }),
      );
    });

    it("uses the remaining Active threads when the first one settles elsewhere during the request", async () => {
      const pendingSettle = deferred<{ ok: true; reclaim: typeof SETTLED_NOTHING }>();
      let firstSettled = false;
      const rendered = renderSlot(inbox, { ...listProps, activeThreadId: "current" }, {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "first", title: "First active", createdAt: 30 }),
            thread({ id: "second", title: "Second active", createdAt: 20 }),
            thread({ id: "current", title: "Current", createdAt: 10 }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: firstSettled ? [
            { threadId: "first", settledAt: Date.now(), snoozedUntil: null, snoozedAt: null },
          ] : [] }),
          [action]: () => pendingSettle.promise,
        },
      });
      const current = (await screen.findByText("Current")).closest("li")!;
      await parkFromCard(current, action);
      await waitFor(() => expect(rendered.rpcCalls.some(call => call.method === action)).toBe(true));

      firstSettled = true;
      await rendered.emitRealtime("lifecycle", {});
      await waitFor(() => expect(
        within(screen.getByRole("region", { name: "Active" })).queryByText("First active"),
      ).toBeNull());
      pendingSettle.resolve({ ok: true, reclaim: SETTLED_NOTHING });
      await waitFor(() => expect(rendered.sidebarActionCalls).toContainEqual({
        method: "open", threadId: "second",
      }));
    });

  });

  describe.each([
    ["Parked", "settle"],
    ["Parked", "snooze"],
    ["Snoozed", "settle"],
    ["Snoozed", "park"],
    ["Settled", "snooze"],
    ["Settled", "park"],
  ] as const)("%s compact card: %s", (shelf, action) => {
    it.each(["pinned", "active", "empty"])("follows the same navigation with %s candidates", async (destination) => {
      const now = Date.now();
      const rendered = renderSlot(inbox, { ...listProps, activeThreadId: "current" }, {
        sidebarThreads: {
          status: "ready",
          threads: [
            thread({ id: "current", title: "Current" }),
            ...(destination === "pinned" ? [
              thread({ id: "first-pin", title: "First pin", isPinned: true }),
              thread({ id: "second-pin", title: "Second pin", isPinned: true }),
            ] : []),
            ...(destination !== "empty" ? [
              thread({ id: "first-active", title: "First active", updatedAt: now, createdAt: 200 }),
              thread({ id: "last-active", title: "Last active", updatedAt: now, createdAt: 100 }),
            ] : []),
            thread({ id: "inactive", title: "Inactive" }),
          ],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        settings: { inactiveThreadsEnabled: true, inactiveAfterHours: "6" },
        rpc: {
          listLifecycle: () => ({ rows: [{
            threadId: "current",
            parkedAt: shelf === "Parked" ? now : null,
            settledAt: shelf === "Settled" ? now : null,
            snoozedUntil: shelf === "Snoozed" ? now + 60_000 : null,
            snoozedAt: shelf === "Snoozed" ? now : null,
          }] }),
          [action]: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
        },
      });

      const region = await screen.findByRole("region", { name: shelf });
      await parkFromMenu(within(region).getByText("Current"), action);
      await waitFor(() => expect(rendered.sidebarActionCalls).toEqual([
        destination === "empty"
          ? { method: "openNewThread", options: { projectId: "proj_1", focusPrompt: true } }
          : { method: "open", threadId: destination === "pinned" ? "first-pin" : "first-active" },
      ]));
    });
  });

  it("reminds the user what settling released and what it left running", async () => {
    renderSlot(
      inbox,
      { ...listProps, activeThreadId: "only" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "only", title: "Only thread" })],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          settle: () => ({
            ok: true,
            reclaim: {
              closedTerminals: 1,
              keptTerminals: 2,
              stoppedRuntime: true,
            },
          }),
        },
      },
    );

    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() =>
      expect(toastMocks.success).toHaveBeenCalledWith(
        "Thread settled",
        expect.objectContaining({
          description:
            "Agent session stopped · closed 1 terminal nobody used · 2 terminals left running",
          duration: 10_000,
        }),
      ),
    );
  });

  it.each(parkingActions)("does not override navigation while %s is in flight", async (action) => {
    const pendingSettle =
      deferred<{ ok: true; reclaim: typeof SETTLED_NOTHING }>();
    const props = { ...listProps, activeThreadId: "slow" };
    const rendered = renderSlot(inbox, props, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "slow", title: "Slow settle", createdAt: 20 }),
          thread({ id: "elsewhere", title: "Elsewhere", createdAt: 10 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        [action]: () => pendingSettle.promise,
      },
    });

    await parkFromMenu(await screen.findByText("Slow settle"), action);
    await waitFor(() =>
      expect(rendered.rpcCalls.filter((call) => call.method === action))
        .toHaveLength(1),
    );
    const InboxComponent = inbox.component;
    rendered.rerender(
      <InboxComponent {...props} activeThreadId="elsewhere" />,
    );
    pendingSettle.resolve({ ok: true, reclaim: SETTLED_NOTHING });
    await waitFor(() => expect(toastMocks.success).toHaveBeenCalled());
    expect(
      rendered.sidebarActionCalls.filter(
        (call) => call.method === "open" || call.method === "openNewThread",
      ),
    ).toEqual([]);
  });

  it("appends the reclaim reminder after the snooze wake time", async () => {
    let wakeAt = 0;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "loud", title: "Loud snooze" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        snooze: (input) => {
          wakeAt = (input as { snoozedUntil: number }).snoozedUntil;
          return {
            ok: true,
            reclaim: {
              closedTerminals: 0,
              keptTerminals: 1,
              stoppedRuntime: true,
            },
          };
        },
      },
    });

    const snooze = await screen.findByRole("combobox", {
      name: "Snooze thread",
    });
    fireEvent.keyDown(snooze, { key: "Enter" });
    fireEvent.click(await screen.findByRole("option", { name: "1 hour" }));
    await waitFor(() =>
      expect(toastMocks.success).toHaveBeenCalledWith(
        "Thread snoozed",
        expect.objectContaining({
          description: `Wakes ${formatSnoozeWakeTime(wakeAt)} · Agent session stopped · 1 terminal left running`,
          duration: 10_000,
        }),
      ),
    );
  });

  it("deduplicates snooze, confirms the wake time, and supports Undo", async () => {
    const pendingSnooze =
      deferred<{ ok: true; reclaim: typeof SETTLED_NOTHING }>();
    let wakeAt = 0;
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "dedupe", title: "Dedupe snooze" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        snooze: (input) => {
          wakeAt = (input as { snoozedUntil: number }).snoozedUntil;
          return pendingSnooze.promise;
        },
        unsnooze: () => ({ ok: true }),
      },
    });

    const snooze = await screen.findByRole("combobox", {
      name: "Snooze thread",
    });
    fireEvent.keyDown(snooze, { key: "Enter" });
    fireEvent.click(
      await screen.findByRole("option", { name: "1 hour" }),
    );
    fireEvent.keyDown(snooze, { key: "Enter" });
    fireEvent.click(await screen.findByRole("option", { name: "Wait refresh (5 hours)" }));
    await waitFor(() =>
      expect(rendered.rpcCalls.filter((call) => call.method === "snooze"))
        .toHaveLength(1),
    );

    pendingSnooze.resolve({ ok: true, reclaim: SETTLED_NOTHING });
    await waitFor(() =>
      expect(toastMocks.success).toHaveBeenCalledWith(
        "Thread snoozed",
        expect.objectContaining({
          description: `Wakes ${formatSnoozeWakeTime(wakeAt)}`,
        }),
      ),
    );
    const toastOptions = toastMocks.success.mock.calls.find(
      ([message]) => message === "Thread snoozed",
    )![1] as { action: { label: string; onClick: () => void } };
    expect(toastOptions.action.label).toBe("Undo");
    toastOptions.action.onClick();
    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "unsnooze",
        input: { threadId: "dedupe" },
      }),
    );
  });

  it("asks to close owned ports after settling, and only closes on confirmation", async () => {
    const ports = [{ port: 3000, pid: 123 }];
    const close = vi.fn(() => ({ signalled: [3000], skipped: [], failed: [] }));
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_ports", title: "Port owner" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        settle: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
        getThreadPorts: () => ({ ports }),
        closeThreadPorts: close,
      },
    });
    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() => expect(toastMocks.message).toHaveBeenCalledWith("Close this thread's ports?", expect.anything()));
    expect(close).not.toHaveBeenCalled();
    const options = toastMocks.message.mock.calls.find(([message]) => message === "Close this thread's ports?")![1];
    await act(async () => options.action.onClick());
    expect(close).toHaveBeenCalledWith({ threadId: "thr_ports", ports });
  });

  it("supports Undo after settling and un-settling a thread", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "round-trip", title: "Round trip" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        settle: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
        unsettle: () => ({ ok: true }),
      },
    });

    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() =>
      expect(toastMocks.success).toHaveBeenCalledWith(
        "Thread settled",
        expect.objectContaining({
          action: expect.objectContaining({ label: "Undo" }),
        }),
      ),
    );
    const settleToast = toastMocks.success.mock.calls.find(
      ([message]) => message === "Thread settled",
    )![1] as { action: { onClick: () => void } };
    settleToast.action.onClick();

    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "unsettle",
        input: { threadId: "round-trip" },
      }),
    );
    const unsettleToast = toastMocks.success.mock.calls.find(
      ([message]) => message === "Thread returned to the inbox",
    )![1] as { action: { label: string; onClick: () => void } };
    expect(unsettleToast.action.label).toBe("Undo");
    unsettleToast.action.onClick();

    await waitFor(() =>
      expect(
        rendered.rpcCalls.filter(
          (call) =>
            call.method === "settle" &&
            (call.input as { threadId: string }).threadId === "round-trip",
        ),
      ).toHaveLength(2),
    );
  });

  it("restores the original wake time when undoing an unsnooze", async () => {
    const wakeAt = Date.now() + 3_600_000;
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "wake", title: "Wake round trip" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "wake",
              settledAt: null,
              snoozedUntil: wakeAt,
              snoozedAt: Date.now(),
            },
          ],
        }),
        unsnooze: () => ({ ok: true }),
        snooze: () => ({ ok: true, reclaim: SETTLED_NOTHING }),
      },
    });

    const shelf = await screen.findByRole("region", { name: "Snoozed" });
    fireEvent.click(within(shelf).getByRole("button"));
    fireEvent.click(within(shelf).getByLabelText("Wake thread now"));
    await waitFor(() =>
      expect(toastMocks.success).toHaveBeenCalledWith(
        "Thread woke up",
        expect.objectContaining({
          action: expect.objectContaining({ label: "Undo" }),
        }),
      ),
    );
    const wakeToast = toastMocks.success.mock.calls.find(
      ([message]) => message === "Thread woke up",
    )![1] as { action: { onClick: () => void } };
    wakeToast.action.onClick();

    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "snooze",
        input: { threadId: "wake", snoozedUntil: wakeAt },
      }),
    );
  });

  it.each(parkingActions)("reports %s failures and leaves the active route alone", async (action) => {
    const rendered = renderSlot(
      inbox,
      { ...listProps, activeThreadId: "broken" },
      {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "broken", title: "Broken settle" })],
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          [action]: () => {
            throw new Error("database offline");
          },
        },
      },
    );

    await parkFromCard((await screen.findByText("Broken settle")).closest("li")!, action);
    await waitFor(() =>
      expect(toastMocks.error).toHaveBeenCalledWith(
        `Could not ${action} thread`,
        { description: "database offline" },
      ),
    );
    expect(
      rendered.sidebarActionCalls.some(
        (call) => call.method === "open" || call.method === "openNewThread",
      ),
    ).toBe(false);
  });

  it("offers Un-settle on settled rows and Wake now on snoozed rows", async () => {
    const calls: string[] = [];
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "settled", title: "Settled row" }),
          thread({ id: "snoozed", title: "Snoozed row" }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            {
              threadId: "settled",
              settledAt: Date.now(),
              snoozedUntil: null,
              snoozedAt: null,
            },
            {
              threadId: "snoozed",
              settledAt: null,
              snoozedUntil: Date.now() + 3_600_000,
              snoozedAt: Date.now(),
            },
          ],
        }),
        unsettle: (input) => {
          calls.push(`unsettle:${(input as { threadId: string }).threadId}`);
          return { ok: true };
        },
        unsnooze: (input) => {
          calls.push(`unsnooze:${(input as { threadId: string }).threadId}`);
          return { ok: true };
        },
      },
    });

    await waitFor(() =>
      expect(
        rendered.inspection.rpcCalls.some(
          (call) => call.method === "listLifecycle",
        ),
      ).toBe(true),
    );
    const settledShelf = await screen.findByRole("region", { name: "Settled" });
    const snoozedShelf = await screen.findByRole("region", { name: "Snoozed" });
    fireEvent.click(within(settledShelf).getByRole("button"));
    fireEvent.click(within(snoozedShelf).getByRole("button"));

    fireEvent.contextMenu(within(settledShelf).getByText("Settled row"));
    let menu = await screen.findByRole("menu", { name: "Thread actions" });
    expect(within(menu).getByText("Un-settle")).toBeDefined();
    expect(within(menu).getByText("Rename")).toBeDefined();
    expect(within(menu).queryByText("Wake now")).toBeNull();
    fireEvent.click(within(menu).getByText("Un-settle"));
    await waitFor(() => expect(calls).toContain("unsettle:settled"));

    fireEvent.contextMenu(within(snoozedShelf).getByText("Snoozed row"));
    menu = await screen.findByRole("menu", { name: "Thread actions" });
    expect(within(menu).getByText("Wake now")).toBeDefined();
    expect(within(menu).getByText("Rename")).toBeDefined();
    expect(within(menu).queryByText("Un-settle")).toBeNull();
    fireEvent.click(within(menu).getByText("Wake now"));
    await waitFor(() => expect(calls).toContain("unsnooze:snoozed"));
  });

  for (const busyThread of [
    thread({ id: "running", title: "Running row", indicator: "runtime" }),
    thread({
      id: "pending",
      title: "Pending row",
      hasPendingInteraction: true,
    }),
  ]) {
    it(`disables Archive while ${busyThread.id}`, async () => {
      const rendered = render([busyThread]);
      fireEvent.contextMenu(await screen.findByText(busyThread.title!));
      const archive = within(
        await screen.findByRole("menu", { name: "Thread actions" }),
      ).getByText("Archive");
      expect(archive.getAttribute("data-disabled")).not.toBeNull();
      fireEvent.click(archive);
      expect(rendered.sidebarActionCalls).not.toContainEqual({
        method: "archive",
        threadId: busyThread.id,
      });
    });
  }

  it("regenerates from the menu and disables repeated clicks while waiting", async () => {
    const result = deferred<{ title: string }>();
    const regenerateTitle = vi.fn((_input: unknown) => result.promise);
    renderSlot(inbox, listProps, {
      sidebarThreads: { status: "ready", threads: [thread({ title: "Original title" })], projects: [] },
      rpc: { listLifecycle: () => ({ rows: [] }), regenerateTitle },
    });
    fireEvent.contextMenu(await screen.findByText("Original title"));
    fireEvent.click(screen.getByRole("menuitem", { name: "Regenerate title" }));
    await waitFor(() => expect(regenerateTitle).toHaveBeenCalledTimes(1));
    expect(regenerateTitle.mock.calls[0]?.[0]).toEqual({ threadId: "thr_1" });
    expect(screen.queryByRole("menu")).toBeNull();
    expect(screen.getByRole("status", { name: "Generating title" })).toBeTruthy();
    fireEvent.contextMenu(screen.getByText("Original title"));
    expect(screen.getByRole("menuitem", { name: "Regenerating title…" }).getAttribute("aria-disabled")).toBe("true");
    result.resolve({ title: "New title" });
    await waitFor(() => expect(toastMocks.success).toHaveBeenCalledWith("Thread title regenerated"));
    expect(screen.queryByRole("status", { name: "Generating title" })).toBeNull();
    expect(regenerateTitle).toHaveBeenCalledTimes(1);
  });

  it("shows regeneration errors and keeps the existing title", async () => {
    renderSlot(inbox, listProps, {
      sidebarThreads: { status: "ready", threads: [thread({ title: "Original title" })], projects: [] },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        regenerateTitle: () => { throw new Error("Title service unavailable"); },
      },
    });
    fireEvent.contextMenu(await screen.findByText("Original title"));
    fireEvent.click(screen.getByRole("menuitem", { name: "Regenerate title" }));
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith("Could not regenerate title", {
      description: "Title service unavailable",
    }));
    expect(screen.getByText("Original title")).toBeTruthy();
    expect(screen.queryByRole("status", { name: "Generating title" })).toBeNull();
  });

  it("renames from the menu and saves with Enter", async () => {
    const rendered = render([
      thread({ id: "thr_rename", title: "Original title" }),
    ]);
    const row = await screen.findByRole("link", { name: "Original title" });
    act(() => row.focus());
    fireEvent.contextMenu(row);
    fireEvent.click(within(await screen.findByRole("menu")).getByText("Rename"));

    const input = await screen.findByRole("textbox", {
      name: "Rename Original title",
    });
    // Let the menu's deferred focus restoration finish before typing.
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    expect(document.activeElement).toBe(input);
    expect(input.isConnected).toBe(true);
    fireEvent.change(input, { target: { value: "Updated title" } });
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "rename",
        threadId: "thr_rename",
        title: "Updated title",
      }),
    );
  });

  it("supports double-click rename, Escape cancel, and blur save", async () => {
    const rendered = render([
      thread({ id: "thr_inline", title: "Inline title" }),
    ]);
    const row = await screen.findByRole("link", { name: "Inline title" });

    fireEvent.doubleClick(row);
    let input = await screen.findByRole("textbox", {
      name: "Rename Inline title",
    });
    fireEvent.change(input, { target: { value: "Canceled title" } });
    fireEvent.keyDown(input, { key: "Escape" });
    expect(
      rendered.sidebarActionCalls.some((call) => call.method === "rename"),
    ).toBe(false);

    fireEvent.doubleClick(row);
    input = await screen.findByRole("textbox", { name: "Rename Inline title" });
    fireEvent.change(input, { target: { value: "Blurred title" } });
    fireEvent.blur(input);
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "rename",
        threadId: "thr_inline",
        title: "Blurred title",
      }),
    );
  });

  it("copies the branch, thread ID, and thread link", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    render([
      thread({
        id: "thr_copy",
        title: "Copy data",
        environment: {
          id: "env_1",
          name: "Worktree",
          branchName: "feature/context-menu",
          workspaceDisplayKind: "managed-worktree",
        },
      }),
    ]);

    const openCopyMenu = async () => {
      fireEvent.contextMenu(await screen.findByText("Copy data"));
      const menu = await screen.findByRole("menu", { name: "Thread actions" });
      const copy = within(menu).getByRole("menuitem", { name: "Copy" });
      fireEvent.click(copy);
      const firstCopyAction = await screen.findByText("Copy branch");
      return firstCopyAction.closest<HTMLElement>('[role="menu"]')!;
    };

    let copyMenu = await openCopyMenu();
    fireEvent.click(within(copyMenu).getByText("Copy branch"));
    await waitFor(() =>
      expect(writeText).toHaveBeenCalledWith("feature/context-menu"),
    );

    copyMenu = await openCopyMenu();
    fireEvent.click(within(copyMenu).getByText("Copy thread ID"));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith("thr_copy"));

    copyMenu = await openCopyMenu();
    fireEvent.click(within(copyMenu).getByText("Copy thread link"));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(
      `${window.location.origin}/projects/proj_1/threads/thr_copy`,
    ));
  });

  it("copies personal thread links and reports clipboard failures", async () => {
    const writeText = vi.fn(() => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: { writeText },
    });
    render([thread({ id: "thr_personal", title: "Personal thread" })], [
      { id: "proj_1", name: "Personal", isPersonal: true },
    ]);
    const copyLink = async () => {
      fireEvent.contextMenu(await screen.findByText("Personal thread"));
      fireEvent.click(screen.getByRole("menuitem", { name: "Copy" }));
      fireEvent.click(await screen.findByText("Copy thread link"));
    };
    await copyLink();
    await waitFor(() => expect(writeText).toHaveBeenCalledWith(
      `${window.location.origin}/threads/thr_personal`,
    ));
    writeText.mockRejectedValueOnce(new Error("Clipboard denied"));
    await copyLink();
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith(
      "Failed to copy thread link",
    ));
  });

  it("confirms deletion with the thread title and project before deleting", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "thr_del", title: "Delete me" }),
          thread({ id: "thr_child", title: "Child", parentThreadId: "thr_del" }),
          thread({ id: "thr_grandchild", title: "Grandchild", parentThreadId: "thr_child" }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      providers: { status: "ready", providers: defaultProviders },
      rpc: { listLifecycle: () => ({ rows: [] }), deleteThread: () => ({ ok: true }) },
    });
    fireEvent.contextMenu(await screen.findByText("Delete me"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    fireEvent.click(within(menu).getByText("Delete"));

    const dialog = await screen.findByRole("dialog", { name: "Delete thread?" });
    expect(within(dialog).getByText("Delete me")).toBeTruthy();
    expect(within(dialog).getByText("bb")).toBeTruthy();
    expect(within(dialog).getByText(/its 2 child threads/)).toBeTruthy();
    expect(rendered.rpcCalls.filter((call) => call.method === "deleteThread")).toEqual([]);
    expect(rendered.sidebarActionCalls).not.toContainEqual(
      expect.objectContaining({ method: "requestDelete" }),
    );

    fireEvent.click(within(dialog).getByRole("button", { name: "Delete thread" }));
    await waitFor(() =>
      expect(rendered.rpcCalls).toContainEqual({
        method: "deleteThread",
        input: { threadId: "thr_del", childThreadsConfirmed: true },
      }),
    );
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Delete thread?" })).toBeNull(),
    );
  });

  it("cancelling the delete confirmation deletes nothing", async () => {
    const rendered = render([thread({ id: "thr_keep", title: "Keep me" })]);
    fireEvent.contextMenu(await screen.findByText("Keep me"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    fireEvent.click(within(menu).getByText("Delete"));
    const dialog = await screen.findByRole("dialog", { name: "Delete thread?" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog", { name: "Delete thread?" })).toBeNull(),
    );
    expect(rendered.rpcCalls.filter((call) => call.method === "deleteThread")).toEqual([]);
  });

  it("uses custom snooze times from plugin settings", async () => {
    let snoozed: { threadId: string; snoozedUntil: number } | null = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_snooze", title: "Snooze me" })],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: { snoozePresets: "15m, Lunch break=3h" },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        snooze: (input) => {
          snoozed = input as { threadId: string; snoozedUntil: number };
          return { ok: true };
        },
      },
    });

    const before = Date.now();
    const snooze = await screen.findByRole("combobox", {
      name: "Snooze thread",
    });
    fireEvent.keyDown(snooze, { key: "Enter" });
    fireEvent.click(
      await screen.findByRole("option", { name: "15 minutes" }),
    );
    await waitFor(() => expect(snoozed).not.toBeNull());
    expect(snoozed!.threadId).toBe("thr_snooze");
    expect(snoozed!.snoozedUntil).toBeGreaterThanOrEqual(
      before + 15 * 60_000,
    );

    fireEvent.contextMenu(await screen.findByText("Snooze me"));
    const menu = await screen.findByRole("menu", { name: "Thread actions" });
    expect(within(menu).getByText("Snooze").getAttribute("aria-haspopup")).toBe(
      "menu",
    );
  });

  it.each(["clock", "context"])("uses the five calendar presets from the %s menu", async (menuType) => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date(2026, 0, 5, 22));
    try {
      const snooze = vi.fn(() => ({ ok: true }));
      renderSlot(inbox, listProps, {
        sidebarThreads: {
          status: "ready",
          threads: [thread({ id: "thr_calendar", title: "Calendar snooze", updatedAt: Date.now() })],
          projects: [],
        },
        rpc: {
          getSidebarSettings: () => ({ ...defaultSidebarSettings, snoozePresets: DEFAULT_SNOOZE_PRESET_CONFIG }),
          listLifecycle: () => ({ rows: [] }),
          snooze,
        },
      });
      let menu: HTMLElement;
      if (menuType === "clock") {
        fireEvent.keyDown(await screen.findByRole("combobox", { name: "Snooze thread" }), { key: "Enter" });
        menu = await screen.findByRole("listbox");
      } else {
        fireEvent.contextMenu(await screen.findByText("Calendar snooze"));
        fireEvent.click(await screen.findByRole("menuitem", { name: "Snooze" }));
        menu = (await screen.findByRole("menuitem", { name: "1 hour" })).closest<HTMLElement>('[role="menu"]')!;
      }
      const role = menuType === "clock" ? "option" : "menuitem";
      expect(within(menu).getAllByRole(role).slice(0, 5).map(item => item.textContent)).toEqual([
        "1 hour", "Wait refresh (5 hours)", "This evening", "Tomorrow morning", "Next week",
      ]);
      const evening = within(menu).getByRole(role, { name: "This evening" });
      expect(evening.getAttribute("aria-disabled")).toBe("true");
      fireEvent.click(evening);
      expect(snooze).not.toHaveBeenCalled();
      // An open menu must resolve against the date when the user selects it.
      vi.setSystemTime(new Date(2026, 0, 6, 0, 1));
      fireEvent.click(within(menu).getByRole(role, { name: "Tomorrow morning" }));
      await waitFor(() => expect(snooze).toHaveBeenCalledWith({
        threadId: "thr_calendar", snoozedUntil: new Date(2026, 0, 7, 9).getTime(),
      }));
    } finally {
      cleanup();
      vi.useRealTimers();
    }
  });
});

describe("card metadata", () => {
  it("always shows the provider glyph, even without a branch", async () => {
    render([thread({ id: "thr_p", providerId: "claude-code" })]);
    expect(await screen.findByLabelText("Claude Code")).toBeDefined();
  });

  it("falls back to a neutral glyph for an unknown provider", async () => {
    render([thread({ id: "thr_p", providerId: "some-new-agent" })]);
    expect(await screen.findByLabelText("some-new-agent")).toBeDefined();
  });

  // A personal-project thread has a machine but no worktree, so the machine
  // takes the branch's place instead of leaving the line blank.
  it("shows the machine when the thread has no branch", async () => {
    render([
      thread({
        id: "thr_m",
        host: { id: "host_1", name: "Dev MacBook" },
      }),
    ]);
    expect(await screen.findByText("Dev MacBook")).toBeDefined();
  });

  it("prefers the branch over the machine when both exist", async () => {
    render([
      thread({
        id: "thr_b",
        host: { id: "host_1", name: "Dev MacBook" },
        environment: {
          id: "env_1",
          name: "Worktree",
          branchName: "bb/feature",
          workspaceDisplayKind: "managed-worktree",
        },
      }),
    ]);
    expect(await screen.findByText("bb/feature")).toBeDefined();
    expect(screen.queryByText("Dev MacBook")).toBeNull();
    expect(await screen.findByLabelText("Worktree branch")).toBeDefined();
    expect(
      screen.getByLabelText("Machine: Dev MacBook"),
    ).toBeDefined();
  });

  it("shows a plain branch cue for non-worktree checkouts", async () => {
    render([
      thread({
        id: "thr_checkout",
        environment: {
          id: "env_1",
          name: "Checkout",
          branchName: "main",
          workspaceDisplayKind: "other",
        },
      }),
    ]);
    expect(await screen.findByLabelText("Branch")).toBeDefined();
    expect(screen.queryByLabelText("Worktree branch")).toBeNull();
  });

  it.each([
    ["managed-worktree", "FolderGit", "Worktree branch"],
    ["unmanaged-worktree", "FolderGit", "Worktree branch"],
    ["other", "GitBranch", "Branch"],
  ] as const)("shows one branch line with matching icons for %s", async (workspaceDisplayKind, icon, branchLabel) => {
    render([
      thread({
        title: "Unnamed worktree thread",
        environment: {
          id: "env_worktree",
          name: null,
          branchName: "bb/feature",
          workspaceDisplayKind,
        },
      }),
    ]);

    expect(screen.getByLabelText(branchLabel).getAttribute("data-icon")).toBe(icon);
    act(() => screen.getByRole("link", { name: "Unnamed worktree thread" }).focus());
    const details = await screen.findByRole("dialog", { name: "Thread details" });
    const label = within(details).getByText(`${branchLabel}:`);
    expect(label.className).toContain("sr-only");
    expect(label.parentElement?.previousElementSibling?.getAttribute("data-icon")).toBe(icon);
    expect(within(details).getAllByText("bb/feature")).toHaveLength(1);
  });

  it("reduces read idle emphasis without weakening unread rows", async () => {
    render([
      thread({ id: "read", title: "Read row", createdAt: 20 }),
      thread({
        id: "unread",
        title: "Unread row",
        isUnread: true,
        createdAt: 10,
      }),
    ]);
    const read = (await screen.findByText("Read row")).closest(
      "[data-row-emphasis]",
    );
    const unread = screen
      .getByText("Unread row")
      .closest("[data-row-emphasis]");
    expect(read?.getAttribute("data-row-emphasis")).toBe("read-idle");
    expect(read?.className).toContain("text-muted-foreground");
    expect(unread?.getAttribute("data-row-emphasis")).toBe("unread");
    expect(unread?.className).toContain("font-medium");
    expect(unread?.className).toContain("text-foreground");
  });

  it("shows the shared details card on the main thread without an icon tooltip", async () => {
    render([
      thread({
        id: "thr_details",
        title: "Thread metadata",
        providerId: "claude-code",
        host: { id: "host_1", name: "Build Mac" },
        environment: {
          id: "env_1",
          name: "Feature worktree",
          branchName: "bb/details",
          workspaceDisplayKind: "unmanaged-worktree",
        },
        activity: {
          workflows: 1,
          backgroundAgents: 2,
          backgroundCommands: 0,
          planMode: 0,
          goals: 1,
        },
      }),
    ]);

    expect(screen.queryByLabelText("Thread details")).toBeNull();
    fireEvent.pointerMove(await screen.findByRole("link", { name: "Thread metadata" }), { pointerType: "mouse" });
    const details = await screen.findByRole("dialog", { name: "Thread details" });
    expect(details.textContent).toContain("Project: bb");
    expect(details.textContent).not.toContain("Feature worktree");
    expect(details.textContent).toContain("Worktree branch: bb/details");
    expect(details.textContent).toContain("Machine: Build Mac");
    expect(details.textContent).toContain("Provider: Claude Code");
    expect(details.textContent).toContain("Model:");
    expect(within(details).queryByRole("list", { name: "Subthreads" })).toBeNull();
  });

  // Not exactly 3h: the card's clock is quantized to the minute, so a
  // timestamp sitting on a bucket boundary legitimately reads one unit lower.
  it("shows how long ago the thread was touched", async () => {
    render([
      thread({ id: "thr_t", updatedAt: Date.now() - (3 * 3_600_000 + 60_000) }),
    ]);
    expect(await screen.findByText("3h")).toBeDefined();
  });

  // Status and age share one slot. Live work uses a short readable label;
  // idle rows use their age.
  it("replaces the age label with a readable status while work runs", async () => {
    render([
      thread({
        id: "thr_run",
        indicator: "runtime",
        indicatorLabel: "Agent is working",
        updatedAt: Date.now() - (3 * 3_600_000 + 60_000),
      }),
    ]);
    expect(await screen.findByLabelText("Agent is working")).toBeDefined();
    expect(screen.getByText("Working").className).toContain(
      "text-[color:var(--bb-sidebar-tone-working)]",
    );
    expect(screen.queryByText("3h")).toBeNull();
  });

  // The host says only that a thread is working, so the sidebar keeps its own
  // stamp per thread and shows how long the current stretch has run.
  it("shows how long a thread has been working", async () => {
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ thr_run: Date.now() - 5 * 60_000 - 60_000 }),
    );
    render([thread({ id: "thr_run", indicator: "runtime" })]);
    expect(await screen.findByText("Working · 5m")).toBeDefined();
  });

  it("shows monitoring when BB identifies a monitoring runtime", async () => {
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ thr_monitor: Date.now() - 5 * 60_000 - 60_000 }),
    );
    render([
      thread({
        id: "thr_monitor",
        indicator: "runtime",
        indicatorLabel: "Thread monitoring",
      }),
    ]);
    expect(await screen.findByText("Monitoring · 5m")).toBeDefined();
    expect(screen.getByLabelText("Thread monitoring")).toBeDefined();
  });

  it("stamps a thread that starts working and persists the stamp", async () => {
    render([thread({ id: "thr_run", indicator: "runtime" })]);
    expect(await screen.findByText("Working")).toBeDefined();
    await waitFor(() => {
      const stored = JSON.parse(
        window.localStorage.getItem("bb-sidebar:working-since:v1") ?? "{}",
      ) as Record<string, number>;
      expect(typeof stored.thr_run).toBe("number");
    });
  });

  // A request for input is a verdict, not a stretch of work, and reads oddly
  // with a duration behind it.
  it("leaves the duration off a status that is waiting on the user", async () => {
    window.localStorage.setItem(
      "bb-sidebar:working-since:v1",
      JSON.stringify({ thr_ask: Date.now() - 10 * 60_000 }),
    );
    render([
      thread({
        id: "thr_ask",
        indicator: "waiting-for-input",
        hasPendingInteraction: true,
      }),
    ]);
    expect(await screen.findByText("Needs you")).toBeDefined();
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

// The three states that need attention take the slot from the age label.
describe("attention states", () => {
  const states = [
    [
      "waiting-for-input",
      "Thread needs user input",
      "Needs you",
      "text-[color:var(--bb-sidebar-tone-pending)]",
    ],
    [
      "unread-error",
      "Unread thread failed",
      "Failed",
      "text-[color:var(--bb-sidebar-tone-error)]",
    ],
    [
      "unread-success",
      "Unread thread succeeded",
      "Unread",
      "text-[color:var(--bb-sidebar-tone-success)]",
    ],
  ] as const;

  for (const [indicator, label, shortLabel, toneClass] of states) {
    it(`shows the ${indicator} label instead of the age`, async () => {
      render([
        thread({
          id: `thr_${indicator}`,
          indicator,
          indicatorLabel: label,
          updatedAt: Date.now() - (3 * 3_600_000 + 60_000),
        }),
      ]);
      expect(await screen.findByLabelText(label)).toBeDefined();
      expect(screen.getByText(shortLabel).className).toContain(toneClass);
      expect(screen.queryByText("3h")).toBeNull();
    });
  }

  it("uses a working label instead of an unread success state", async () => {
    render([
      thread({
        id: "thr_busy",
        isUnread: true,
        indicator: "runtime",
        indicatorLabel: "Thread working",
      }),
    ]);
    expect(await screen.findByLabelText("Thread working")).toBeDefined();
    expect(screen.getByText("Working")).toBeDefined();
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

  it("links the PR number out to the git host", async () => {
    withPr("none");
    const badge = await screen.findByRole("link", { name: "#412" });
    expect(badge.getAttribute("href")).toBe("https://github.com/o/r/pull/412");
    expect(badge.getAttribute("title")).toBeNull();
    fireEvent.focus(badge);
    expect((await screen.findByRole("tooltip")).textContent).toBe(
      "Fix the flake\nOpen",
    );
  });

  it("shows no badge when the branch has no PR", async () => {
    render([thread({ id: "thr_nopr" })]);
    await screen.findByText("A thread");
    expect(screen.queryByRole("link", { name: /^#/ })).toBeNull();
  });

  // BB's richer attention state keeps failed open PRs red while other open
  // states use the emerald pull request color.
  it("colors the badge from the attention state", async () => {
    const failing = withPr("checks_failed");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-[color:var(--bb-sidebar-pr-alert)]");
    failing.unmount();

    withPr("ready_to_merge");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-[color:var(--bb-sidebar-pr-open)]");
  });

  it("covers pending, review, draft, closed, and merged states", async () => {
    const pending = withPr("checks_pending");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-[color:var(--bb-sidebar-pr-open)]");
    pending.unmount();

    const review = withPr("review_requested");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-[color:var(--bb-sidebar-pr-open)]");
    review.unmount();

    const draft = withPr("draft", "draft");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-muted-foreground/60");
    draft.unmount();

    const closed = withPr("closed", "closed");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-[color:var(--bb-sidebar-pr-alert)]");
    closed.unmount();

    withPr("merged", "merged");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-[color:var(--bb-sidebar-pr-merged)]");
  });
});


it("keeps parked threads parked when opened and offers Resume with Undo", async () => {
  const resume = vi.fn(() => ({ ok: true }));
  const park = vi.fn(() => ({ ok: true, reclaim: SETTLED_NOTHING }));
  const rendered = renderSlot(inbox, listProps, {
    sidebarThreads: {
      status: "ready",
      threads: [thread({ id: "waiting", title: "Awaiting review", isPinned: true })],
      projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
    },
    rpc: {
      listLifecycle: () => ({ rows: [{ threadId: "waiting", parkedAt: Date.now() - 5 * 86400000, settledAt: null, snoozedUntil: null, snoozedAt: null }] }),
      resume,
      park,
    },
  });
  const shelf = await screen.findByRole("region", { name: "Parked" });
  fireEvent.click(within(shelf).getByRole("button"));
  expect(within(shelf).getByText("Waiting 5d")).toBeDefined();
  fireEvent.click(within(shelf).getByRole("link", { name: "bb · Awaiting review" }));
  expect(resume).not.toHaveBeenCalled();
  expect(rendered.sidebarActionCalls).toContainEqual({ method: "open", threadId: "waiting", options: { split: false } });
  fireEvent.click(within(shelf).getByRole("button", { name: "Resume thread" }));
  await waitFor(() => expect(resume).toHaveBeenCalled());
  const toast = toastMocks.success.mock.calls.find(([message]) => message === "Thread returned to the inbox");
  expect(toast).toBeDefined();
  act(() => toast![1].action.onClick());
  await waitFor(() => expect(park).toHaveBeenCalled());
});


describe("parent thread menu", () => {
  it("orders parent choices by recent activity regardless of pin, shelf, or sidebar sort", async () => {
    const now = Date.now();
    localStorage.setItem("bb-sidebar:active-sort:v1", "created");
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "child", title: "Choose my parent", updatedAt: now }),
          thread({ id: "settled", title: "Settled parent", updatedAt: now - 1_000 }),
          thread({ id: "active", title: "Active parent", updatedAt: now - 4_000, createdAt: now - 4_000 }),
          thread({ id: "inactive", title: "Older parent" }),
          thread({ id: "pinned", title: "Pinned parent", isPinned: true, updatedAt: now - 9_000 }),
          thread({ id: "snoozed", title: "Snoozed parent", updatedAt: now - 3_000 }),
          thread({ id: "pinned-2", title: "Pinned second", isPinned: true, updatedAt: now - 7_000 }),
          thread({ id: "parked", title: "Parked parent", updatedAt: now - 5_000 }),
          thread({ id: "hidden", title: "Nested work", parentThreadId: "settled", updatedAt: now - 2_000 }),
          thread({ id: "nested-active", title: "Nested active work", parentThreadId: "active", updatedAt: now - 6_000 }),
          thread({ id: "nested-pinned", title: "Nested pinned work", parentThreadId: "settled", isPinned: true, updatedAt: now - 8_000 }),
          thread({ id: "orphan", title: "Orphan parent", parentThreadId: "missing", updatedAt: now - 10_000 }),
          thread({ id: "descendant", title: "Forbidden pinned child", parentThreadId: "child", isPinned: true }),
          thread({ id: "other", title: "Foreign pinned thread", projectId: "proj_other", isPinned: true }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }, { id: "proj_other", name: "docs", isPersonal: false }],
      },
      rpc: {
        getSidebarSettings: () => ({ ...defaultSidebarSettings, inactiveThreadsEnabled: true, inactiveAfterHours: 6 }),
        listLifecycle: () => ({ rows: [
          { threadId: "settled", settledAt: now, snoozedUntil: null, snoozedAt: null },
          { threadId: "snoozed", settledAt: null, snoozedUntil: now + 3_600_000, snoozedAt: now },
          { threadId: "parked", settledAt: null, snoozedUntil: null, snoozedAt: null, parkedAt: now },
        ] }),
      },
    });
    await screen.findByRole("region", { name: "Inactive" });
    await screen.findByRole("region", { name: "Settled" });
    fireEvent.contextMenu(await screen.findByText("Choose my parent"));
    fireEvent.keyDown(screen.getByRole("menuitem", { name: "Parent" }), { key: "ArrowRight" });
    const search = await screen.findByRole("textbox", { name: "Search parent threads" });
    const menu = search.closest<HTMLElement>('[role="menu"]')!;
    expect(within(menu).getAllByRole("menuitemradio").map(item => item.textContent)).toEqual([
      "None", "Settled parent", "Nested work", "Snoozed parent", "Active parent",
      "Parked parent", "Nested active work", "Pinned second", "Nested pinned work",
      "Pinned parent", "Orphan parent", "Older parent", "docs · Foreign pinned thread",
    ]);
    expect(within(menu).queryByRole("separator")).toBeNull();
    expect(within(menu).getByRole("menuitemradio", { name: "Pinned parent" }).querySelector('[data-icon="Pin"]')).not.toBeNull();

    fireEvent.change(search, { target: { value: "pinned" } });
    expect(within(menu).getAllByRole("menuitemradio").map(item => item.textContent)).toEqual(["None", "Pinned second", "Nested pinned work", "Pinned parent", "docs · Foreign pinned thread"]);
    expect(within(menu).queryByRole("separator")).toBeNull();
    fireEvent.change(search, { target: { value: "docs" } });
    expect(within(menu).getAllByRole("menuitemradio").map(item => item.textContent)).toEqual(["None", "docs · Foreign pinned thread"]);
    fireEvent.change(search, { target: { value: "older" } });
    expect(within(menu).getAllByRole("menuitemradio").map(item => item.textContent)).toEqual(["None", "Older parent"]);
    expect(within(menu).queryByRole("separator")).toBeNull();
    fireEvent.change(search, { target: { value: "settled" } });
    expect(within(menu).getAllByRole("menuitemradio").map(item => item.textContent)).toEqual(["None", "Settled parent"]);
    expect(within(menu).queryByRole("separator")).toBeNull();
  });

  async function openParentMenu(setThreadParent = vi.fn(() => ({ ok: true }))) {
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "child", title: "Choose my parent", parentThreadId: "old" }),
          thread({ id: "old", title: "Current parent", isArchived: true }),
          thread({ id: "next", title: "Next parent" }),
          thread({ id: "descendant", title: "Forbidden child", parentThreadId: "child" }),
          thread({ id: "grandchild", title: "Forbidden grandchild", parentThreadId: "descendant" }),
          thread({ id: "other", title: "Other project", projectId: "proj_other" }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: { listLifecycle: () => ({ rows: [] }), setThreadParent },
    });
    fireEvent.contextMenu(await screen.findByText("Choose my parent"));
    const trigger = within(await screen.findByRole("menu", { name: "Thread actions" })).getByText("Parent");
    fireEvent.keyDown(trigger, { key: "ArrowRight" });
    const search = await screen.findByRole("textbox", { name: "Search parent threads" });
    await waitFor(() => expect(document.activeElement).toBe(search));
    return { menu: search.closest('[role="menu"]') as HTMLElement, setThreadParent };
  }

  it("searches safe candidates and assigns a parent with the keyboard", async () => {
    const { menu, setThreadParent } = await openParentMenu();
    expect(within(menu).queryByText("Choose my parent")).toBeNull();
    expect(within(menu).queryByText("Forbidden child")).toBeNull();
    expect(within(menu).queryByText("Forbidden grandchild")).toBeNull();
    expect(within(menu).queryByText("Other project")).toBeNull();
    expect(within(menu).getByRole("menuitemradio", { name: "Current parent" }).getAttribute("aria-checked")).toBe("true");
    const input = within(menu).getByRole("textbox", { name: "Search parent threads" });
    fireEvent.change(input, { target: { value: "NEXT" } });
    expect(within(menu).getByRole("menuitemradio", { name: "Next parent" })).toBeDefined();
    fireEvent.keyDown(input, { key: "ArrowUp" });
    expect(document.activeElement).toBe(within(menu).getByRole("menuitemradio", { name: "Next parent" }));
    fireEvent.keyDown(document.activeElement!, { key: "Enter" });
    await waitFor(() => expect(setThreadParent).toHaveBeenCalledWith({ threadId: "child", parentThreadId: "next" }));
  });

  it("offers None even with no search matches and removes the parent", async () => {
    const { menu, setThreadParent } = await openParentMenu();
    fireEvent.change(within(menu).getByRole("textbox"), { target: { value: "no match" } });
    expect(within(menu).getByText("No matching threads")).toBeDefined();
    fireEvent.click(within(menu).getByRole("menuitemradio", { name: "None" }));
    await waitFor(() => expect(setThreadParent).toHaveBeenCalledWith({ threadId: "child", parentThreadId: null }));
  });

  it("reports a rejected parent change", async () => {
    const { menu } = await openParentMenu(vi.fn(() => { throw new Error("Parent is no longer available"); }));
    fireEvent.click(within(menu).getByRole("menuitemradio", { name: "Next parent" }));
    await waitFor(() => expect(toastMocks.error).toHaveBeenCalledWith("Could not update parent", { description: "Parent is no longer available" }));
  });
});
