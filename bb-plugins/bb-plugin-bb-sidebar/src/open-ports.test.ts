import { describe, expect, it } from "vitest";
import { portsByEnvironment } from "./open-ports";

describe("workspace port indicators", () => {
  it("counts a port once across listening addresses and keeps environments separate", () => {
    const result = portsByEnvironment({
      groups: [
        { environmentId: "env_a", ports: [{ port: 8080 }, { port: 3000 }, { port: 3000 }] },
        { environmentId: "env_b", ports: [{ port: 5432 }] },
      ],
    });
    expect(result.get("env_a")).toEqual([{ port: 3000 }, { port: 8080 }]);
    expect(result.get("env_b")).toEqual([{ port: 5432 }]);
    expect(result.get("env_missing")).toBeUndefined();
  });

});
