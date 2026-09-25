import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createFakePluginHost,
  makeThreadResponse,
} from "@get-bb/plugin-sdk/testing";
import plugin from "./server";
import { lastUserMessages, parseTitle } from "./regenerate-title";

const disposers: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.all(disposers.splice(0).map((dispose) => dispose()));
});

function message(id: number, text: string, extra = {}) {
  return {
    kind: "conversation",
    role: "user",
    initiator: "user",
    id: String(id),
    text,
    createdAt: id,
    sourceSeqStart: id,
    turnRequest: { status: "accepted" },
    ...extra,
  };
}
function page(rows: unknown[], older = false) {
  return {
    rows,
    timelinePage: {
      hasOlderRows: older,
      olderCursor: older ? { anchorId: "older", anchorSeq: 4 } : null,
    },
  };
}

async function setup() {
  const { bb, harness } = createFakePluginHost({ pluginId: "bb-sidebar" });
  const sdk = harness.inspection.sdk;
  sdk.stub("threads.get", async () =>
    makeThreadResponse({ id: "target", title: "Original title" }),
  );
  sdk.stub("threads.timeline", async () =>
    page([
      message(1, "Old excluded request"),
      message(2, "Build a sidebar"),
      message(3, "Add title regeneration"),
      message(4, "Use three user messages"),
      message(5, "Assistant must be excluded", { role: "assistant" }),
    ]),
  );
  sdk.stub("system.config", async () => ({
    aiServices: {
      inference: "codex/primary",
      inferenceFallback: "codex/fallback",
    },
  }));
  sdk.stub("providers.list", async () => [{ id: "codex", available: true }]);
  sdk.stub("projects.list", async () => [{ id: "personal", kind: "personal" }]);
  sdk.stub("threads.spawn", async () => makeThreadResponse({ id: "helper" }));
  sdk.stub("threads.wait", async () => ({ matched: true }));
  sdk.stub("threads.output", async () => ({
    output: '{"title":"Regenerate sidebar titles"}',
  }));
  sdk.stub("threads.stop", async () => ({ ok: true }));
  sdk.stub("threads.delete", async () => ({ ok: true }));
  sdk.stub("threads.update", async () =>
    makeThreadResponse({ title: "Regenerate sidebar titles" }),
  );
  await plugin(bb);
  disposers.push(() => harness.lifecycle.dispose());
  return {
    bb,
    harness,
    sdk,
    run: () =>
      harness.behavior.callRpc("regenerateTitle", { threadId: "target" }),
  };
}

describe("title regeneration", () => {
  it("sends only the last three user texts in order and saves the title", async () => {
    const { sdk, run } = await setup();
    await expect(run()).resolves.toEqual({
      title: "Regenerate sidebar titles",
    });
    const spawn = sdk.callsTo("threads.spawn")[0]![0] as { prompt: string };
    expect(JSON.parse(spawn.prompt.split("\n\n").at(-1)!)).toEqual([
      "Build a sidebar",
      "Add title regeneration",
      "Use three user messages",
    ]);
    expect(spawn).toMatchObject({
      projectId: "personal",
      providerId: "codex",
      model: "primary",
      visibility: "hidden",
      environment: { type: "host", workspace: { type: "personal" } },
    });
    expect(spawn).not.toHaveProperty("parentThreadId");
    expect(spawn).not.toHaveProperty("sourceThreadId");
    expect(sdk.callsTo("threads.update")[0]![0]).toEqual({
      threadId: "target",
      title: "Regenerate sidebar titles",
    });
    expect(sdk.callsTo("threads.stop")).toHaveLength(1);
    expect(sdk.callsTo("threads.delete")[0]![0]).toEqual({
      threadId: "helper",
      childThreadsConfirmed: true,
    });
  });

  it("pages past system, assistant, and pending rows, retaining repeated user messages", async () => {
    const { bb, sdk } = await setup();
    sdk.stub(
      "threads.timeline",
      vi
        .fn()
        .mockResolvedValueOnce(
          page(
            [
              message(8, "System", { initiator: "system" }),
              message(7, "Queued", { turnRequest: { status: "pending" } }),
              { kind: "turn", children: [message(6, "Repeat")] },
              message(5, "Assistant", { role: "assistant" }),
            ],
            true,
          ),
        )
        .mockResolvedValueOnce(
          page([
            message(2, "Opening message"),
            message(3, "Repeat"),
            message(6, "Repeat"),
          ]),
        ),
    );
    expect(await lastUserMessages(bb, "target")).toEqual([
      "Opening message",
      "Repeat",
      "Repeat",
    ]);
    expect(sdk.callsTo("threads.timeline")[1]![0]).toMatchObject({
      beforeAnchorId: "older",
      beforeAnchorSeq: "4",
    });
  });

  it("uses fewer than three messages and caps each message", async () => {
    const { bb, sdk } = await setup();
    sdk.stub("threads.timeline", async () =>
      page([message(1, "a".repeat(9_000)), message(2, "")]),
    );
    expect(
      (await lastUserMessages(bb, "target")).map((text) => text.length),
    ).toEqual([8_000, 0]);
  });

  it("does not generate or rename when the selected messages have no text", async () => {
    const { sdk, run } = await setup();
    sdk.stub("threads.timeline", async () => page([message(1, "")]));
    await expect(run()).rejects.toThrow("no user-message text");
    expect(sdk.callsTo("threads.spawn")).toHaveLength(0);
    expect(sdk.callsTo("threads.update")).toHaveLength(0);
  });

  it("keeps the existing title and cleans up after invalid output", async () => {
    const { sdk, run } = await setup();
    sdk.stub("threads.output", async () => ({
      output: "I will edit the project",
    }));
    await expect(run()).rejects.toThrow("invalid title");
    expect(sdk.callsTo("threads.spawn")).toHaveLength(1);
    expect(sdk.callsTo("threads.update")).toHaveLength(0);
    expect(sdk.callsTo("threads.delete")).toHaveLength(1);
  });

  it("retries a timeout with the configured fallback and cleans up both attempts", async () => {
    const { sdk, run } = await setup();
    sdk.stub(
      "threads.wait",
      vi
        .fn()
        .mockRejectedValueOnce(new Error("timed out"))
        .mockResolvedValueOnce({ matched: true }),
    );
    await run();
    expect(
      sdk
        .callsTo("threads.spawn")
        .map((call) => (call[0] as { model: string }).model),
    ).toEqual(["primary", "fallback"]);
    expect(sdk.callsTo("threads.delete")).toHaveLength(2);
  });

  it("preserves a manual rename made while generating", async () => {
    const { sdk, run } = await setup();
    sdk.stub(
      "threads.get",
      vi
        .fn()
        .mockResolvedValueOnce(makeThreadResponse({ title: "Original title" }))
        .mockResolvedValueOnce(makeThreadResponse({ title: "Manual title" })),
    );
    await expect(run()).rejects.toThrow("newer title was kept");
    expect(sdk.callsTo("threads.update")).toHaveLength(0);
  });

  it("deduplicates simultaneous requests for the same thread", async () => {
    const { sdk, run } = await setup();
    await Promise.all([run(), run()]);
    expect(sdk.callsTo("threads.spawn")).toHaveLength(1);
    expect(sdk.callsTo("threads.update")).toHaveLength(1);
  });

  it("rejects malformed or long titles", () => {
    for (const output of [
      null,
      "{}",
      '{"title":""}',
      '{"title":"one two three four five six"}',
      "[]",
    ]) {
      expect(() => parseTitle(output)).toThrow();
    }
    expect(parseTitle('```json\n{"title":"  Sidebar   titles "}\n```')).toBe(
      "Sidebar titles",
    );
  });
});
