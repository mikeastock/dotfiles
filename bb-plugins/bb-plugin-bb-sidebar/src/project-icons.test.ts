import { describe, expect, it } from "vitest";
import {
  extractProjectIconHref,
  iconPathsForHref,
  normalizeProjectIconPath,
  projectIconUrl,
} from "./project-icons";

describe("project icon paths", () => {
  it("accepts supported project-relative image paths", () => {
    expect(normalizeProjectIconPath("./public/brand.svg")).toBe(
      "public/brand.svg",
    );
    expect(normalizeProjectIconPath("assets\\icon.PNG")).toBe(
      "assets/icon.PNG",
    );
  });

  it("rejects traversal, absolute paths, URLs, and non-images", () => {
    expect(normalizeProjectIconPath("../secret.svg")).toBeNull();
    expect(normalizeProjectIconPath("/tmp/icon.svg")).toBeNull();
    expect(normalizeProjectIconPath("https://example.com/icon.svg")).toBeNull();
    expect(normalizeProjectIconPath("README.md")).toBeNull();
  });

  it("extracts local icon links without accepting remote assets", () => {
    const href = extractProjectIconHref(
      '<html><link sizes="any" href="/favicon.svg?v=2" rel="icon"></html>',
    );
    expect(href).toBe("/favicon.svg");
    expect(iconPathsForHref(href!)).toEqual([
      "public/favicon.svg",
      "favicon.svg",
    ]);
    expect(iconPathsForHref("https://example.com/icon.svg")).toEqual([]);
    expect(
      extractProjectIconHref(
        'export const links = () => [{ href: "assets/icon.png", rel: "icon" }];',
      ),
    ).toBe("assets/icon.png");
  });

  it("builds one scoped route per project and revision", () => {
    expect(projectIconUrl("proj one", 3)).toBe(
      "/api/v1/plugins/bb-sidebar/http/project-icon?projectId=proj+one&revision=3",
    );
  });
});
