import { describe, expect, it } from "vitest";
import { isBbInternalListener, parseProcessCommands } from "./port-processes";

describe("BB internal port filtering", () => {
  it.each([
    ["bb Nightly", "/Applications/bb Nightly.app/Contents/MacOS/bb Nightly /Applications/bb Nightly.app/Contents/Resources/app.asar.unpacked/node_modules/bb-app/host-daemon/dist/bb-provider-bridge-worker.mjs"],
    ["node", "/usr/bin/node /opt/node_modules/bb-app/server/dist/index.js"],
    ["bb", "/usr/bin/bb"],
    ["bb Nightly", ""],
  ])("excludes the BB runtime %s", (name, command) => {
    expect(isBbInternalListener(name, command)).toBe(true);
  });

  it.each([
    ["git-history", "git-history"],
    ["node", "/usr/bin/node /workspace/server.js"],
    ["python3", "python3 -m http.server 49631"],
    ["bb-api", "bb-api"],
    ["bb Nightly", "/Applications/bb Nightly.app/Contents/MacOS/bb Nightly /workspace/server.js"],
  ])("keeps the user server %s", (name, command) => {
    expect(isBbInternalListener(name, command)).toBe(false);
  });

  it("reads commands containing spaces without losing the executable path", () => {
    expect(parseProcessCommands("  123 /Applications/bb Nightly.app/Contents/MacOS/bb Nightly\n  456 node server.js\n")).toEqual(new Map([
      [123, "/Applications/bb Nightly.app/Contents/MacOS/bb Nightly"],
      [456, "node server.js"],
    ]));
  });
});
