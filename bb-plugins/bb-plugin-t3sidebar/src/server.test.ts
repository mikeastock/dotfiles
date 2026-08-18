import { afterEach, describe, expect, it } from "vitest";
import { createFakePluginHost } from "@get-bb/plugin-sdk/testing";
import { createPlugin } from "./server";

type Host = ReturnType<typeof createFakePluginHost>;

interface LifecycleRows {
  rows: {
    threadId: string;
    settledAt: number | null;
    snoozedUntil: number | null;
    snoozedAt: number | null;
  }[];
}

/** The fields runSweep reads off a threads.list row; the rest is bb's. */
function listThread(
  id: string,
  environmentId: string | null = "env_1",
  overrides: Record<string, unknown> = {},
) {
  return {
    id,
    status: "idle",
    pinnedAt: null,
    visibility: "visible",
    environmentId,
    hasPendingInteraction: false,
    activity: {
      activeWorkflowCount: 0,
      activeBackgroundAgentCount: 0,
      activeBackgroundCommandCount: 0,
      activePlanModeCount: 0,
      activeGoalCount: 0,
    },
    ...overrides,
  };
}

const MERGED_PR = {
  outcome: "available",
  pullRequest: {
    state: "merged",
    url: "https://github.com/acme/app/pull/42",
  },
};

const hosts: Host[] = [];

async function setup(options: {
  threads?: unknown[];
  pullRequest?: (args: { environmentId: string }) => unknown;
  settings?: Record<string, boolean>;
  /** What the open-PR verification returns; undefined branches = no open PRs. */
  openPrBranches?: (repo: string) => Promise<Set<string> | null>;
}): Promise<Host> {
  const host = createFakePluginHost({
    pluginId: "t3sidebar",
    settings: options.settings,
    sdk: {
      projects: { list: async () => [{ id: "proj_1" }] },
      threads: { list: async () => options.threads ?? [] },
      environments: {
        pullRequest:
          options.pullRequest ?? (async () => ({ outcome: "absent" })),
      },
    },
  });
  hosts.push(host);
  const plugin = createPlugin({
    listOpenPrBranches:
      options.openPrBranches ?? (async () => new Set<string>()),
  });
  await plugin(host.bb);
  return host;
}

afterEach(async () => {
  while (hosts.length > 0) {
    await hosts.pop()!.harness.lifecycle.dispose();
  }
});

function lifecycleSignals(host: Host) {
  return host.harness.inspection.realtimeSignals.filter(
    (signal) => signal.channel === "lifecycle",
  );
}

async function lifecycleRows(host: Host): Promise<LifecycleRows["rows"]> {
  const result = (await host.harness.behavior.callRpc(
    "listLifecycle",
    {},
  )) as LifecycleRows;
  return result.rows;
}

describe("pr-merge-sweep", () => {
  it("settles a quiet thread whose PR merged, once", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => MERGED_PR,
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    const rows = await lifecycleRows(host);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      threadId: "thr_1",
      snoozedUntil: null,
      snoozedAt: null,
    });
    expect(rows[0]!.settledAt).toEqual(expect.any(Number));
    expect(
      host.harness.inspection.sdk.callsTo("environments.pullRequest"),
    ).toHaveLength(1);
    expect(lifecycleSignals(host)).toHaveLength(1);

    // A repeated tick with unchanged GitHub state is a no-op: the settled
    // thread is parked, so it is never even re-probed.
    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toEqual(rows);
    expect(
      host.harness.inspection.sdk.callsTo("environments.pullRequest"),
    ).toHaveLength(1);
    expect(lifecycleSignals(host)).toHaveLength(1);
  });

  it("never re-settles after a manual un-settle (the user-overrule rule)", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => MERGED_PR,
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");
    expect(await lifecycleRows(host)).toHaveLength(1);

    await host.harness.behavior.callRpc("unsettle", { threadId: "thr_1" });
    expect(await lifecycleRows(host)).toHaveLength(0);

    // The PR is still merged, but the overrule marker names this exact PR
    // url: the sweep must not undo the user's call. (It does re-probe — the
    // overrule check needs the current url, which only the lookup provides.)
    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toHaveLength(0);
    expect(
      host.harness.inspection.sdk.callsTo("environments.pullRequest"),
    ).toHaveLength(2);
  });

  it("treats an unavailable lookup as no information", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => ({
        outcome: "unavailable",
        message: "gh is not authenticated",
      }),
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toHaveLength(0);
    expect(lifecycleSignals(host)).toHaveLength(0);
  });

  it("does not settle a closed-unmerged PR by default", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => ({
        outcome: "available",
        pullRequest: {
          state: "closed",
          url: "https://github.com/acme/app/pull/42",
        },
      }),
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toHaveLength(0);
  });

  it("settles a closed-unmerged PR when the settleClosed setting is on", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      settings: { settleClosed: true },
      pullRequest: async () => ({
        outcome: "available",
        pullRequest: {
          state: "closed",
          url: "https://github.com/acme/app/pull/42",
        },
      }),
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    const rows = await lifecycleRows(host);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.threadId).toBe("thr_1");
  });

  it("is a no-op when the autoSettle setting is off", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      settings: { autoSettle: false },
      pullRequest: async () => MERGED_PR,
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toHaveLength(0);
    expect(host.harness.inspection.sdk.callsTo("threads.list")).toHaveLength(0);
  });

  it("never parks live work, even when its PR merged", async () => {
    const host = await setup({
      threads: [
        listThread("thr_working", "env_1", { status: "active" }),
        listThread("thr_blocked", "env_1", { hasPendingInteraction: true }),
        listThread("thr_pinned", "env_1", { pinnedAt: 123 }),
        listThread("thr_workflow", "env_1", {
          activity: {
            activeWorkflowCount: 1,
            activeBackgroundAgentCount: 0,
            activeBackgroundCommandCount: 0,
            activePlanModeCount: 0,
            activeGoalCount: 0,
          },
        }),
        listThread("thr_done", "env_1"),
      ],
      pullRequest: async () => MERGED_PR,
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    const rows = await lifecycleRows(host);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.threadId).toBe("thr_done");
    // All five threads share one environment: exactly one probe.
    expect(
      host.harness.inspection.sdk.callsTo("environments.pullRequest"),
    ).toHaveLength(1);
  });

  it("does not settle while the thread has other open PRs, then settles once they clear", async () => {
    // The serial-PR workflow: the environment's recorded branch merged, but
    // the thread has already pushed bb/<slug>-<threadId> branches with open
    // PRs. One merged PR does not make the thread terminal.
    let openBranches: Set<string> = new Set([
      "bb/kit-plan-operation-domain-thr_1",
      "bb/kit-speech-state-domain-thr_1",
    ]);
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => MERGED_PR,
      openPrBranches: async () => openBranches,
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toHaveLength(0);
    expect(lifecycleSignals(host)).toHaveLength(0);

    // The observation was recorded without a marker, so once the siblings
    // merge or close, the next tick settles the thread.
    openBranches = new Set();
    await host.harness.behavior.runSchedule("pr-merge-sweep");

    const rows = await lifecycleRows(host);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.threadId).toBe("thr_1");
  });

  it("fails closed when open-PR verification cannot run", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => MERGED_PR,
      openPrBranches: async () => null,
    });

    await host.harness.behavior.runSchedule("pr-merge-sweep");

    expect(await lifecycleRows(host)).toHaveLength(0);
  });

  it("leaves manually settled rows intact across the added migration", async () => {
    const host = await setup({
      threads: [listThread("thr_1")],
      pullRequest: async () => MERGED_PR,
    });

    await host.harness.behavior.callRpc("settle", { threadId: "thr_9" });
    await host.harness.behavior.runSchedule("pr-merge-sweep");

    const threadIds = (await lifecycleRows(host))
      .map((row) => row.threadId)
      .sort();
    expect(threadIds).toEqual(["thr_1", "thr_9"]);
  });
});
