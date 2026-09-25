import { describe, expect, it } from "vitest";
import { portBrowserUrl } from "./port-links";

describe("port browser links", () => {
  it("requires an explicit matching device and rejects remote or unknown hosts", () => {
    expect(portBrowserUrl({ port: 3000 }, "local", "local")).toBe("http://127.0.0.1:3000/");
    expect(portBrowserUrl({ port: 3000 }, "remote", "local")).toBeNull();
    expect(portBrowserUrl({ port: 3000 }, "local", null)).toBeNull();
    expect(portBrowserUrl({ port: 3000 }, undefined, "local")).toBeNull();
  });
  it("honors IPv6 and concrete bind addresses", () => {
    expect(portBrowserUrl({ port: 3000, address: "::1" }, "local", "local")).toBe("http://[::1]:3000/");
    expect(portBrowserUrl({ port: 3000, address: "::" }, "local", "local")).toBe("http://[::1]:3000/");
    expect(portBrowserUrl({ port: 3000, address: "192.168.1.5" }, "local", "local")).toBe("http://192.168.1.5:3000/");
    expect(portBrowserUrl({ port: 8443, address: "0.0.0.0" }, "local", "local")).toBe("https://127.0.0.1:8443/");
  });
  it("does not link known non-web services or malformed addresses", () => {
    expect(portBrowserUrl({ port: 5432 }, "local", "local")).toBeNull();
    expect(portBrowserUrl({ port: 23456, service: "postgres" }, "local", "local")).toBeNull();
    expect(portBrowserUrl({ port: 3000, address: "example.com/path" }, "local", "local")).toBeNull();
  });
});
