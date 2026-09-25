import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { experimental_createHostEntryHarness } from "@get-bb/plugin-sdk/testing/host";

const mocks = vi.hoisted(() => ({ run: vi.fn(), platform: vi.fn() }));
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  const { promisify } = await import("node:util");
  return { ...actual, execFile: Object.assign(vi.fn(), { [promisify.custom]: mocks.run }) };
});
vi.mock("node:os", async (importOriginal) => ({ ...await importOriginal<typeof import("node:os")>(), platform: mocks.platform }));
vi.mock("node:fs/promises", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:fs/promises")>(),
  realpath: async (path: string) => path,
}));
import entry from "./ports-host";

const roots = [{ environmentId: "env_a", path: "/workspace/app" }];
const sockets = `COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
node 123 u 1u IPv4 0x1 0t0 TCP 127.0.0.1:3000 (LISTEN)
node 456 u 1u IPv4 0x2 0t0 TCP 127.0.0.1:4000 (LISTEN)
`;
let harness: ReturnType<typeof experimental_createHostEntryHarness<typeof entry.contract, {}>>;

beforeEach(() => {
  mocks.run.mockReset();
  mocks.platform.mockReturnValue("darwin");
  harness = experimental_createHostEntryHarness(entry);
});
afterEach(async () => { await harness.experimental_dispose(); });

function commands(docker: () => string = () => "") {
  mocks.run.mockImplementation(async (command: string, args: string[]) => {
    if (command === "lsof") return { stdout: args.includes("-d") ? "p123\nfcwd\nn/workspace/app\np456\nfcwd\nn/workspace/app\n" : sockets };
    if (command === "ps") return { stdout: args[0] === "eww"
      ? "node app.js BB_THREAD_ID=thr_owner PATH=/bin"
      : "123 node app.js\n456 node /opt/bb-app/server/dist/index.js" };
    if (command === "docker") return { stdout: docker() };
    throw new Error(`Unexpected command ${command}`);
  });
}

describe("host port scan", () => {
  it("enriches process listeners with Docker metadata without losing ownership or bind address", async () => {
    commands(() => "abc\tapp-web-1\t0.0.0.0:3000->3000/tcp, 0.0.0.0:8080->8080/tcp\t/workspace/app\tweb");
    const result = await harness.experimental_call("scan", { roots });
    expect(result.ports).toEqual([
      { environmentId: "env_a", port: 3000, address: "127.0.0.1", pid: 123, processName: "node", source: "process", ownerThreadId: "thr_owner", container: "app-web-1", service: "web" },
      { environmentId: "env_a", port: 8080, address: "0.0.0.0", source: "docker", container: "app-web-1", service: "web" },
    ]);
  });

  it("keeps user listeners and excludes BB listeners when Docker is unavailable", async () => {
    commands(() => { throw new Error("ENOENT"); });
    const result = await harness.experimental_call("scan", { roots: [...roots, { environmentId: "env_b", path: roots[0].path }] });
    expect(result.ports.map(({ environmentId, port, ownerThreadId }) => ({ environmentId, port, ownerThreadId }))).toEqual([
      { environmentId: "env_a", port: 3000, ownerThreadId: "thr_owner" },
      { environmentId: "env_b", port: 3000, ownerThreadId: "thr_owner" },
    ]);
  });

  it("propagates cancellation instead of returning a partial scan", async () => {
    const controller = new AbortController();
    commands(() => { controller.abort(); throw new Error("aborted"); });
    await expect(harness.experimental_call("scan", { roots }, { signal: controller.signal })).rejects.toThrow();
  });
});
