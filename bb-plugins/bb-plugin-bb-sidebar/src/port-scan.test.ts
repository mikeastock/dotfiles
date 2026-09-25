// Adapted from bb-plugin-worktree-ports. See THIRD_PARTY_NOTICES.md.
import { describe, expect, it } from "vitest";
import {
  attribute,
  parseCwds,
  parseDockerPorts,
  parseDockerRows,
  parseListeners,
} from "./port-scan";

const LSOF = `COMMAND     PID      USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
anton      5568 rbiggers    9u  IPv6 0x1a2b3c4d5e6f7890      0t0  TCP *:8089 (LISTEN)
node      91234 rbiggers   23u  IPv4 0x1a2b3c4d5e6f7891      0t0  TCP 127.0.0.1:3000 (LISTEN)
Code\\x20H 49046 rbiggers   17u  IPv4 0x1a2b3c4d5e6f7892      0t0  TCP 127.0.0.1:41729 (LISTEN)
nginx     11111 rbiggers    6u  IPv6 0x1a2b3c4d5e6f7893      0t0  TCP [::1]:8443 (LISTEN)
`;

describe("parseListeners", () => {
  it("reads pid, process, address and port from every family", () => {
    expect(parseListeners(LSOF)).toEqual([
      { pid: 5568, processName: "anton", address: "0.0.0.0", port: 8089 },
      { pid: 91234, processName: "node", address: "127.0.0.1", port: 3000 },
      { pid: 49046, processName: "Code H", address: "127.0.0.1", port: 41729 },
      { pid: 11111, processName: "nginx", address: "::1", port: 8443 },
    ]);
  });

  it("keeps the header and malformed rows out", () => {
    expect(parseListeners("")).toEqual([]);
    expect(parseListeners("COMMAND PID USER\nrubbish\n")).toEqual([]);
  });

  it("refuses an out-of-range port", () => {
    const line = "node 1 u 1u IPv4 0x1 0t0 TCP 127.0.0.1:70000 (LISTEN)";
    expect(parseListeners(`HEADER\n${line}\n`)).toEqual([]);
  });
});

describe("parseCwds", () => {
  it("pairs each pid with its cwd", () => {
    const output = "p5568\nfcwd\nn/Users/x/.bb/worktrees/env_a/anton-go\np90546\nfcwd\nn/Users/x\n";
    expect(parseCwds(output)).toEqual(
      new Map([
        [5568, "/Users/x/.bb/worktrees/env_a/anton-go"],
        [90546, "/Users/x"],
      ]),
    );
  });

  it("ignores a name that arrives before any pid", () => {
    expect(parseCwds("n/orphan\n")).toEqual(new Map());
  });
});

describe("parseDockerPorts", () => {
  it("collapses the IPv4/IPv6 pair of one published port", () => {
    expect(parseDockerPorts("0.0.0.0:21785->6379/tcp, [::]:21785->6379/tcp")).toEqual([
      { port: 21785, address: "0.0.0.0" },
    ]);
  });

  it("skips container ports that are not published", () => {
    expect(parseDockerPorts("6379/tcp")).toEqual([]);
  });

  it("keeps every distinct published port of a container", () => {
    expect(
      parseDockerPorts("0.0.0.0:1025->1025/tcp, 0.0.0.0:8025->8025/tcp"),
    ).toEqual([
      { port: 1025, address: "0.0.0.0" },
      { port: 8025, address: "0.0.0.0" },
    ]);
  });
});

describe("parseDockerRows", () => {
  it("drops containers with no compose working directory", () => {
    const output = [
      "abc\tstack-db-1\t0.0.0.0:5432->5432/tcp\t/work/tree\tdb",
      "def\tstray\t0.0.0.0:9999->9999/tcp\t\t",
    ].join("\n");
    expect(parseDockerRows(output)).toEqual([
      {
        id: "abc",
        name: "stack-db-1",
        workingDir: "/work/tree",
        service: "db",
        ports: [{ port: 5432, address: "0.0.0.0" }],
      },
    ]);
  });

  it("leaves the service null for a container outside compose", () => {
    expect(parseDockerRows("abc\tlone\t0.0.0.0:80->80/tcp\t/work/tree\t")[0]?.service).toBeNull();
  });
});

describe("attribute", () => {
  const roots = [
    { environmentId: "env_a", path: "/w/env_a/repo" },
    { environmentId: "env_b", path: "/w/env_a/repo/chains/one" },
  ];

  it("matches the root itself and anything under it", () => {
    expect(attribute("/w/env_a/repo", roots)).toBe("env_a");
    expect(attribute("/w/env_a/repo/apps/web", roots)).toBe("env_a");
  });

  it("gives a nested worktree to itself, not its parent", () => {
    expect(attribute("/w/env_a/repo/chains/one/pkg", roots)).toBe("env_b");
  });

  it("refuses a sibling path that merely shares a prefix", () => {
    expect(attribute("/w/env_a/repo-other/src", roots)).toBeNull();
    expect(attribute("/elsewhere", roots)).toBeNull();
  });
});

