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
import type {
  PluginSidebarThread,
  PluginThreadListProps,
} from "@get-bb/plugin-sdk";
import { formatSnoozeWakeTime } from "./lifecycle";
import type { SidebarProvider } from "./ProviderGlyph";

const toastMocks = vi.hoisted(() => ({
  success: vi.fn(),
  error: vi.fn(),
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

const defaultSidebarSettings = {
  snoozePresets: "30m, 2h, 1d, 1w",
  inactiveThreadsEnabled: true,
  inactiveAfterHours: 6,
  autoSettleInactive: true,
  autoSettleAfterDays: 3,
  autoSettleOnMerge: true,
  showBots: true,
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

    fireEvent.change(screen.getByLabelText("Snooze shortcuts"), {
      target: { value: "15m, Lunch=3h" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(saved).toEqual({
        ...defaultSidebarSettings,
        snoozePresets: "15m, Lunch=3h",
      }),
    );
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
    fireEvent.click(screen.getByRole("button", { name: "Remove..." }));
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

  it("expands child rows with attention, running state, ages, and navigation", async () => {
    const minute = Math.floor(Date.now() / 60_000) * 60_000;
    const rendered = render([
      thread({ id: "parent", title: "Parent" }),
      thread({
        id: "blocked",
        title: "Blocked child",
        parentThreadId: "parent",
        hasPendingInteraction: true,
        indicator: "waiting-for-input",
        updatedAt: minute - 4 * 60_000,
      }),
      thread({
        id: "running",
        title: "Running child",
        parentThreadId: "parent",
        indicator: "runtime",
        updatedAt: minute - 2 * 60_000,
      }),
      thread({
        id: "idle",
        title: "Idle child",
        parentThreadId: "parent",
        updatedAt: minute - 31 * 60_000,
      }),
    ]);

    const badge = screen.getByRole("button", {
      name: "3 child threads, 1 need you",
    });
    expect(badge.className).toContain("bg-[#fbf0dd]");
    fireEvent.click(badge);

    expect(badge.getAttribute("aria-expanded")).toBe("true");
    expect(badge.querySelector('[data-icon="ChevronUp"]')).not.toBeNull();
    const childList = screen.getByRole("list", { name: "Child threads" });
    expect(childList.getAttribute("data-child-thread-list")).toBe("sidebar");
    expect(within(childList).getByText("Needs you")).toBeDefined();
    expect(within(childList).getByText("Running")).toBeDefined();
    expect(within(childList).getByText("4m")).toBeDefined();
    expect(within(childList).getByText("2m")).toBeDefined();
    expect(within(childList).getByText("31m")).toBeDefined();
    expect(
      within(childList).getByRole("button", {
        name: "Open child thread: Blocked child, Needs you",
      }).parentElement?.className,
    ).toContain("bg-[#fdf6ea]");

    fireEvent.click(
      within(childList).getByRole("button", {
        name: "Open child thread: Running child, Running",
      }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "running",
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

  it("restores child expansion and keeps selection on the parent body", () => {
    window.localStorage.setItem(
      "bb-sidebar:child-expansion:v1",
      JSON.stringify(["parent"]),
    );
    render([
      thread({ id: "parent", title: "Parent" }),
      thread({ id: "child", title: "Child", parentThreadId: "parent" }),
    ]);

    expect(screen.getByRole("list", { name: "Child threads" })).toBeDefined();
    fireEvent.click(screen.getByRole("link", { name: "Parent" }), {
      metaKey: true,
    });
    const parentBody = document.querySelector("[data-parent-card]");
    const childList = screen.getByRole("list", { name: "Child threads" });
    expect(parentBody?.className).toContain("ring-primary/60");
    expect(childList.className).not.toContain("ring-primary/60");
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
            busyChild.hasPendingInteraction ? ", Needs you" : ", Running"
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

  it("uses the platform modifier to select without opening", () => {
    const rendered = render([thread({ id: "thr_split" })]);
    fireEvent.click(screen.getByRole("link"), { metaKey: true });
    expect(rendered.sidebarActionCalls).toEqual([]);
    expect(
      screen.getByRole("toolbar", { name: "1 threads selected" }),
    ).toBeDefined();
  });

  it("gives every bulk icon action a keyboard-visible clue", async () => {
    render([thread({ id: "thr_selected" })]);
    fireEvent.click(screen.getByRole("link"), { metaKey: true });

    const actions = [
      ["button", "Settle selected threads"],
      ["combobox", "Snooze selected threads"],
      ["button", "Mark selected threads read"],
      ["button", "Mark selected threads unread"],
      ["button", "Clear selection"],
    ] as const;

    for (const [role, label] of actions) {
      const trigger = screen.getByRole(role, { name: label });
      fireEvent.focus(trigger);
      expect((await screen.findByRole("tooltip")).textContent).toBe(label);
      fireEvent.blur(trigger);
      await waitFor(() => expect(screen.queryByRole("tooltip")).toBeNull());
    }
  });

  it("extends selection across the visible row order with Shift-click", () => {
    render([
      thread({ id: "a", title: "First", createdAt: 30 }),
      thread({ id: "b", title: "Second", createdAt: 20 }),
      thread({ id: "c", title: "Third", createdAt: 10 }),
    ]);
    const links = screen.getAllByRole("link");
    fireEvent.click(links[0]!, { metaKey: true });
    fireEvent.click(links[2]!, { shiftKey: true });

    expect(document.querySelectorAll('[data-selected="true"]')).toHaveLength(
      3,
    );
    expect(
      screen.getByRole("toolbar", { name: "3 threads selected" }),
    ).toBeDefined();
  });

  it("drops selected rows that leave filtered search results", async () => {
    const rendered = render([
      thread({ id: "keep", title: "Keep match", createdAt: 20 }),
      thread({ id: "drop", title: "Drop row", createdAt: 10 }),
    ]);
    const links = screen.getAllByRole("link");
    fireEvent.click(links[0]!, { metaKey: true });
    fireEvent.click(links[1]!, { metaKey: true });
    const InboxComponent = inbox.component;
    rendered.rerender(
      <InboxComponent {...listProps} searchQuery="keep" />,
    );

    await waitFor(() =>
      expect(
        screen.getByRole("toolbar", { name: "1 threads selected" }),
      ).toBeDefined(),
    );
    expect(document.querySelectorAll('[data-selected="true"]')).toHaveLength(
      1,
    );
  });

  it("marks selected rows read and clears successful selection", async () => {
    const rendered = render([
      thread({ id: "a", title: "First", isUnread: true, createdAt: 20 }),
      thread({ id: "b", title: "Second", isUnread: true, createdAt: 10 }),
    ]);
    const links = screen.getAllByRole("link");
    fireEvent.click(links[0]!, { metaKey: true });
    fireEvent.click(links[1]!, { metaKey: true });
    fireEvent.click(
      screen.getByRole("button", { name: "Mark selected threads read" }),
    );

    await waitFor(() =>
      expect(
        rendered.sidebarActionCalls.filter((call) => call.method === "setRead"),
      ).toHaveLength(2),
    );
    expect(rendered.sidebarActionCalls).toEqual(
      expect.arrayContaining([
        { method: "setRead", threadId: "a", read: true },
        { method: "setRead", threadId: "b", read: true },
      ]),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("toolbar", { name: /threads selected/ }),
      ).toBeNull(),
    );
  });

  it("keeps failed rows selected after a partial bulk settle", async () => {
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "First", createdAt: 20 }),
          thread({ id: "b", title: "Second", createdAt: 10 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        bulkSettle: () => ({
          succeededThreadIds: ["a"],
          failures: [{ threadId: "b", error: "cannot unpin" }],
        }),
      },
    });
    const links = screen.getAllByRole("link");
    fireEvent.click(links[0]!, { metaKey: true });
    fireEvent.click(links[1]!, { metaKey: true });
    fireEvent.click(
      screen.getByRole("button", { name: "Settle selected threads" }),
    );

    await waitFor(() =>
      expect(rendered.rpcCalls.some((call) => call.method === "bulkSettle")).toBe(
        true,
      ),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("toolbar", { name: "1 threads selected" }),
      ).toBeDefined(),
    );
    expect(
      document
        .querySelector('[data-sidebar-thread-id="b"]')
        ?.getAttribute("data-selected"),
    ).toBe("true");
    expect(toastMocks.error).toHaveBeenCalledWith(
      "1 of 2 settle actions failed",
      { description: "cannot unpin" },
    );
  });

  it("bulk snoozes selected rows with a configured preset", async () => {
    let bulkInput: { threadIds: string[]; snoozedUntil: number } | null = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "a", title: "First", createdAt: 20 }),
          thread({ id: "b", title: "Second", createdAt: 10 }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      settings: { snoozePresets: "15m, 2h" },
      rpc: {
        listLifecycle: () => ({ rows: [] }),
        bulkSnooze: (input) => {
          bulkInput = input as { threadIds: string[]; snoozedUntil: number };
          return { succeededThreadIds: ["a", "b"], failures: [] };
        },
      },
    });
    const links = screen.getAllByRole("link");
    fireEvent.click(links[0]!, { metaKey: true });
    fireEvent.click(links[1]!, { metaKey: true });
    fireEvent.keyDown(
      screen.getByRole("combobox", { name: "Snooze selected threads" }),
      { key: "Enter" },
    );
    fireEvent.click(await screen.findByRole("option", { name: "15 minutes" }));

    await waitFor(() => expect(bulkInput).not.toBeNull());
    expect(bulkInput!.threadIds).toEqual(["a", "b"]);
    expect(bulkInput!.snoozedUntil).toBeGreaterThan(Date.now());
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

    staleRead.resolve({ inboxThreadIds: ["a", "b"] });
    await Promise.resolve();
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

  it("keeps policy-settled pinned rows active but respects manual settle", async () => {
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

  it("offers settle and snooze on a parkable thread", async () => {
    render([thread({ id: "thr_park", title: "Quiet" })]);
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
      await screen.findByRole("option", { name: "30 minutes" }),
    ).toBeDefined();
    expect(screen.getByRole("option", { name: "2 hours" })).toBeDefined();
    expect(screen.getByRole("option", { name: "1 day" })).toBeDefined();
    expect(screen.getByRole("option", { name: "1 week" })).toBeDefined();
  });

  it("keeps hover-only snooze controls visible while the menu is open", async () => {
    render([thread({ id: "thr_snooze_anchor", title: "Quiet" })]);

    const snooze = await screen.findByRole("combobox", {
      name: "Snooze thread",
    });
    const controls = snooze.parentElement;
    expect(controls).not.toBeNull();
    expect(controls!.classList.contains("opacity-0")).toBe(true);
    expect(controls!.classList.contains("pointer-events-none")).toBe(true);

    fireEvent.keyDown(snooze, { key: "Enter" });
    await screen.findByRole("option", { name: "30 minutes" });

    expect(controls!.classList.contains("opacity-100")).toBe(true);
    expect(controls!.classList.contains("pointer-events-auto")).toBe(true);
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

  it("marks timer and attention wakes until the user dismisses or opens them", async () => {
    const acknowledged: string[] = [];
    const now = Date.now();
    const rendered = renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [
          thread({ id: "timer", title: "Timer wake", latestAttentionAt: 10 }),
          thread({ id: "attention", title: "Attention wake", latestAttentionAt: now }),
        ],
        projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
      },
      rpc: {
        listLifecycle: () => ({
          rows: [
            { threadId: "timer", settledAt: null, snoozedUntil: now - 1, snoozedAt: 20 },
            { threadId: "attention", settledAt: null, snoozedUntil: now + 60_000, snoozedAt: now - 1 },
          ],
        }),
        acknowledgeWake: (input) => {
          acknowledged.push((input as { threadId: string }).threadId);
          return { ok: true };
        },
      },
    });

    const timerRow = (await screen.findByText("Timer wake")).closest("li")!;
    const attentionRow = screen.getByText("Attention wake").closest("li")!;
    expect(within(timerRow).getByText("Woke")).toBeDefined();
    expect(within(attentionRow).getByText("Woke")).toBeDefined();

    fireEvent.click(within(timerRow).getByRole("button", { name: "Dismiss Woke marker" }));
    fireEvent.click(within(attentionRow).getByRole("link", { name: "Attention wake" }));
    await waitFor(() => expect(acknowledged).toEqual(["timer", "attention"]));
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "attention",
      options: { split: false },
    });
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
    expect(
      within(menu)
        .getAllByRole("menuitem")
        .map((item) => item.textContent),
    ).toEqual([
      "Open in split",
      "Pin",
      "Settle",
      "Snooze",
      "Rename",
      "Mark unread",
      "Copy",
      "Archive",
      "Delete",
    ]);
    expect(within(menu).getAllByRole("separator")).toHaveLength(4);
  });

  it("settles an active thread from the context menu", async () => {
    let settled: string | null = null;
    renderSlot(inbox, listProps, {
      sidebarThreads: {
        status: "ready",
        threads: [thread({ id: "thr_settle", title: "Settle from menu" })],
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

    fireEvent.contextMenu(await screen.findByText("Settle from menu"));
    fireEvent.click(within(await screen.findByRole("menu")).getByText("Settle"));
    await waitFor(() => expect(settled).toBe("thr_settle"));
  });

  it("moves away from the active thread after parking it", async () => {
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
          settle: () => ({ ok: true }),
        },
      },
    );

    fireEvent.contextMenu(await screen.findByText("Current"));
    fireEvent.click(within(await screen.findByRole("menu")).getByText("Settle"));
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "open",
        threadId: "next",
      }),
    );
    expect(navigated).toBe(1);
  });

  it("opens a project-scoped composer when parking the last active thread", async () => {
    const rendered = renderSlot(
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
          settle: () => ({ ok: true }),
        },
      },
    );

    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() =>
      expect(rendered.sidebarActionCalls).toContainEqual({
        method: "openNewThread",
        options: { projectId: "proj_1", focusPrompt: true },
      }),
    );
  });

  it("does not override navigation that happens while parking is in flight", async () => {
    const pendingSettle = deferred<{ ok: true }>();
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
        settle: () => pendingSettle.promise,
      },
    });

    fireEvent.contextMenu(await screen.findByText("Slow settle"));
    fireEvent.click(within(await screen.findByRole("menu")).getByText("Settle"));
    await waitFor(() =>
      expect(rendered.rpcCalls.filter((call) => call.method === "settle"))
        .toHaveLength(1),
    );
    const InboxComponent = inbox.component;
    rendered.rerender(
      <InboxComponent {...props} activeThreadId="elsewhere" />,
    );
    pendingSettle.resolve({ ok: true });
    await waitFor(() => expect(toastMocks.success).toHaveBeenCalled());
    expect(
      rendered.sidebarActionCalls.filter(
        (call) => call.method === "open" || call.method === "openNewThread",
      ),
    ).toEqual([]);
  });

  it("deduplicates snooze, confirms the wake time, and supports Undo", async () => {
    const pendingSnooze = deferred<{ ok: true }>();
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
      await screen.findByRole("option", { name: "30 minutes" }),
    );
    fireEvent.keyDown(snooze, { key: "Enter" });
    fireEvent.click(await screen.findByRole("option", { name: "2 hours" }));
    await waitFor(() =>
      expect(rendered.rpcCalls.filter((call) => call.method === "snooze"))
        .toHaveLength(1),
    );

    pendingSnooze.resolve({ ok: true });
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

  it("reports mutation failures and leaves the active route alone", async () => {
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
          settle: () => {
            throw new Error("database offline");
          },
        },
      },
    );

    fireEvent.click(await screen.findByLabelText("Settle thread"));
    await waitFor(() =>
      expect(toastMocks.error).toHaveBeenCalledWith(
        "Could not settle thread",
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

  it("renames from the menu and saves with Enter", async () => {
    const rendered = render([
      thread({ id: "thr_rename", title: "Original title" }),
    ]);
    fireEvent.contextMenu(await screen.findByText("Original title"));
    fireEvent.click(within(await screen.findByRole("menu")).getByText("Rename"));

    const input = await screen.findByRole("textbox", {
      name: "Rename Original title",
    });
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

  it("copies the branch and thread ID", async () => {
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

  it("lists available thread metadata from the SDK in one tooltip", async () => {
    render([
      thread({
        id: "thr_details",
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

    fireEvent.focus(await screen.findByLabelText("Thread details"));
    const details = await screen.findByRole("tooltip");
    expect(details.textContent).toContain("Project: bb");
    expect(details.textContent).toContain("Environment: Feature worktree");
    expect(details.textContent).toContain("Workspace: Unmanaged worktree");
    expect(details.textContent).toContain("Branch: bb/details");
    expect(details.textContent).toContain("Machine: Build Mac");
    expect(details.textContent).toContain("Provider: Claude Code");
    expect(details.textContent).toContain(
      "Activity: 1 workflow, 2 background agents, 1 goal",
    );
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
    expect(screen.getByText("Working").className).toContain("text-sky-600");
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

// The three states that need attention take the slot from the age label.
describe("attention states", () => {
  const states = [
    [
      "waiting-for-input",
      "Thread needs user input",
      "Needs you",
      "text-indigo-600",
    ],
    ["unread-error", "Unread thread failed", "Failed", "text-red-700"],
    [
      "unread-success",
      "Unread thread succeeded",
      "Unread",
      "text-emerald-700",
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
    ).toContain("text-red-600");
    failing.unmount();

    withPr("ready_to_merge");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-emerald-600");
  });

  it("covers pending, review, draft, closed, and merged states", async () => {
    const pending = withPr("checks_pending");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-emerald-600");
    pending.unmount();

    const review = withPr("review_requested");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-emerald-600");
    review.unmount();

    const draft = withPr("draft", "draft");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-muted-foreground/60");
    draft.unmount();

    const closed = withPr("closed", "closed");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-red-600");
    closed.unmount();

    withPr("merged", "merged");
    expect(
      (await screen.findByRole("link", { name: "#412" })).className,
    ).toContain("text-violet-600");
  });
});

describe("bots shelf", () => {
  function bot(overrides: Record<string, unknown> = {}) {
    return {
      id: "bot_1",
      name: "Reviewer",
      role: "Code review",
      avatar: { color: "#6d5efc", shape: "round", expression: "curious" },
      mainThreadId: "thr_main",
      hiddenUntilActivity: false,
      hiddenAt: null,
      sectionId: null,
      order: 0,
      linkedProjectIds: [],
      ...overrides,
    };
  }

  function available(
    bots: Record<string, unknown>[],
    bindings: { threadId: string; botId: string }[],
    sections: { id: string; name: string; order: number }[] = [],
  ) {
    return { available: true, bots, sections, bindings };
  }

  // Fresh timestamps, or the Inactive shelf claims the rows before the Bots
  // shelf ever sees them.
  const botThreads = () => {
    const now = Date.now();
    const fresh = { updatedAt: now, latestAttentionAt: now, lastReadAt: now };
    return [
      thread({ id: "thr_main", title: "Main chat", createdAt: 3, ...fresh }),
      thread({
        id: "thr_child",
        title: "Child work",
        parentThreadId: "thr_main",
        createdAt: 2,
        ...fresh,
      }),
      thread({ id: "thr_free", title: "Free thread", createdAt: 1, ...fresh }),
    ];
  };

  function renderWithBots(
    threads: PluginSidebarThread[],
    snapshot: unknown,
    options: {
      props?: Partial<PluginThreadListProps>;
      settings?: Partial<typeof defaultSidebarSettings>;
    } = {},
  ) {
    return renderSlot(
      inbox,
      { ...listProps, ...options.props },
      {
        sidebarThreads: {
          status: "ready",
          threads,
          projects: [{ id: "proj_1", name: "bb", isPersonal: false }],
        },
        providers: { status: "ready", providers: defaultProviders },
        rpc: {
          listLifecycle: () => ({ rows: [] }),
          getSidebarSettings: () => ({
            ...defaultSidebarSettings,
            ...options.settings,
          }),
          listBots: () => snapshot,
        },
      },
    );
  }

  it("groups a bot's conversations under the bot and out of Active", async () => {
    renderWithBots(
      botThreads(),
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
    );
    const bots = await screen.findByRole("region", { name: "Bots" });
    expect(within(bots).getByText("Reviewer")).toBeDefined();
    expect(within(bots).getByText("Code review")).toBeDefined();
    const rows = within(bots).getByRole("list", {
      name: "Reviewer's conversations",
    });
    expect(within(rows).getByText("Main chat")).toBeDefined();
    // The child lives in its parent's chip, as everywhere in this list, and
    // still counts toward the bot.
    expect(within(rows).queryByText("Child work")).toBeNull();
    const active = screen.getByRole("region", { name: "Active" });
    expect(within(active).getByText("Free thread")).toBeDefined();
    expect(within(active).queryByText("Main chat")).toBeNull();
  });

  it("opens the bot's main conversation from the bot row", async () => {
    const rendered = renderWithBots(
      botThreads(),
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
    );
    fireEvent.click(
      await screen.findByRole("link", { name: /Reviewer.*open main/ }),
    );
    expect(rendered.sidebarActionCalls).toContainEqual({
      method: "open",
      threadId: "thr_main",
      options: { split: false },
    });
  });

  it("folds a bot's conversations away and still answers for the count", async () => {
    renderWithBots(
      botThreads(),
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
    );
    const bots = await screen.findByRole("region", { name: "Bots" });
    fireEvent.click(
      within(bots).getByLabelText("Collapse Reviewer's conversations"),
    );
    expect(within(bots).queryByText("Main chat")).toBeNull();
    expect(within(bots).getByLabelText("2 conversations")).toBeDefined();
    fireEvent.click(
      within(bots).getByLabelText("Expand Reviewer's conversations"),
    );
    expect(within(bots).getByText("Main chat")).toBeDefined();
  });

  it("folds the whole shelf like the others", async () => {
    renderWithBots(
      botThreads(),
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
    );
    const bots = await screen.findByRole("region", { name: "Bots" });
    fireEvent.click(within(bots).getByRole("button", { name: "Bots" }));
    expect(within(bots).getByText("Bots (1)")).toBeDefined();
    expect(within(bots).queryByText("Reviewer")).toBeNull();
  });

  it("says when a bot's conversation needs you", async () => {
    const threads = botThreads();
    threads[1] = thread({
      ...threads[1]!,
      hasPendingInteraction: true,
      indicator: "waiting-for-input",
      indicatorLabel: "Thread needs user input",
    });
    renderWithBots(
      threads,
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
    );
    const bots = await screen.findByRole("region", { name: "Bots" });
    expect(
      within(bots).getByLabelText("1 conversation needs you"),
    ).toBeDefined();
  });

  it("names a custom section and leaves the main section unnamed", async () => {
    renderWithBots(
      botThreads(),
      available(
        [bot(), bot({ id: "bot_2", name: "Deployer", sectionId: "sec_ops" })],
        [{ threadId: "thr_main", botId: "bot_1" }],
        [{ id: "sec_ops", name: "Ops", order: 0 }],
      ),
    );
    const bots = await screen.findByRole("region", { name: "Bots" });
    expect(within(bots).getByText("Ops")).toBeDefined();
    expect(within(bots).queryByText("Main")).toBeNull();
    const text = bots.textContent ?? "";
    expect(text.indexOf("Reviewer")).toBeLessThan(text.indexOf("Deployer"));
  });

  // A thread must always have a row: a hidden bot's conversations come back
  // to Active as plain cards rather than vanishing with the bot.
  it("keeps a hidden bot's conversations in Active", async () => {
    renderWithBots(
      botThreads(),
      available(
        [bot({ hiddenUntilActivity: true, hiddenAt: 1_000 })],
        [{ threadId: "thr_main", botId: "bot_1" }],
      ),
    );
    expect(await screen.findByText("Main chat")).toBeDefined();
    expect(screen.queryByRole("region", { name: "Bots" })).toBeNull();
    expect(screen.queryByText("Reviewer")).toBeNull();
  });

  it("draws the plain list when the bots plugin is unavailable", async () => {
    renderWithBots(botThreads(), {
      available: false,
      reason: "plugin bots-sidebar is not installed",
    });
    expect(await screen.findByText("Main chat")).toBeDefined();
    expect(screen.queryByRole("region", { name: "Bots" })).toBeNull();
  });

  it("honours the Bots shelf setting without asking the server", async () => {
    const rendered = renderWithBots(
      botThreads(),
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
      { settings: { showBots: false } },
    );
    expect(await screen.findByText("Main chat")).toBeDefined();
    await waitFor(() =>
      expect(
        rendered.inspection.rpcCalls.some(
          (call) => call.method === "getSidebarSettings",
        ),
      ).toBe(true),
    );
    expect(screen.queryByRole("region", { name: "Bots" })).toBeNull();
    expect(
      rendered.inspection.rpcCalls.some((call) => call.method === "listBots"),
    ).toBe(false);
  });

  it("re-reads the bots on the plugin's bots signal", async () => {
    const rendered = renderWithBots(
      botThreads(),
      available([bot()], [{ threadId: "thr_main", botId: "bot_1" }]),
    );
    await screen.findByRole("region", { name: "Bots" });
    const before = rendered.inspection.rpcCalls.filter(
      (call) => call.method === "listBots",
    ).length;
    await rendered.behavior.emitRealtime("bots", { threadId: "thr_new" });
    await waitFor(() =>
      expect(
        rendered.inspection.rpcCalls.filter(
          (call) => call.method === "listBots",
        ).length,
      ).toBe(before + 1),
    );
  });

  it("offers the Bots shelf switch on the settings page", async () => {
    let saved: Record<string, unknown> | null = null;
    renderSlot(sidebarSettings, {}, {
      rpc: {
        getSidebarSettings: () => defaultSidebarSettings,
        updateSidebarSettings: (input) => {
          saved = input as Record<string, unknown>;
          return saved;
        },
        listProjectIconSettings: () => ({ projects: [] }),
      },
    });
    const toggle = await screen.findByRole("switch", { name: "Bots shelf" });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    fireEvent.click(toggle);
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(saved).toEqual({ ...defaultSidebarSettings, showBots: false }),
    );
  });
});
