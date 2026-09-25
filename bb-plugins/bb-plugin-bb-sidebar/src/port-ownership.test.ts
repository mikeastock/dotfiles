import { describe, expect, it } from "vitest";
import { macProcessEnvironment, threadIdFromEnvironment } from "./port-ownership";

describe("listener ownership", () => {
  it("reads an explicit thread marker on Linux and macOS", () => {
    expect(threadIdFromEnvironment("PATH=/bin\0BB_THREAD_ID=thr_owner\0", "nul")).toBe("thr_owner");
    expect(threadIdFromEnvironment("PATH=/bin BB_THREAD_ID=thr_owner", "space")).toBe("thr_owner");
  });
  it("leaves missing, malformed, or ambiguous metadata unassigned", () => {
    for (const value of ["PATH=/bin", "BB_THREAD_ID=", "BB_THREAD_ID=bad", "BB_THREAD_ID=thr_a BB_THREAD_ID=thr_b"]) {
      expect(threadIdFromEnvironment(value, "space")).toBeUndefined();
    }
  });
  it("excludes command arguments and rejects changed commands", () => {
    const command = "node server.js BB_THREAD_ID=thr_wrong";
    const environment = macProcessEnvironment(command, `${command} PATH=/bin BB_THREAD_ID=thr_right`);
    expect(threadIdFromEnvironment(environment, "space")).toBe("thr_right");
    expect(macProcessEnvironment("node old.js", "node new.js BB_THREAD_ID=thr_owner")).toBe("");
    expect(macProcessEnvironment("", "BB_THREAD_ID=thr_owner")).toBe("");
  });
});
