// @vitest-environment jsdom
import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { Tooltip } from "./Tooltip";

afterEach(cleanup);

describe("Tooltip", () => {
  it("shows its clue on pointer hover", async () => {
    render(
      <Tooltip label="Settle thread">
        <button type="button">Action</button>
      </Tooltip>,
    );

    fireEvent.pointerMove(screen.getByRole("button"), {
      pointerType: "mouse",
    });

    expect((await screen.findByRole("tooltip")).textContent).toBe(
      "Settle thread",
    );
  });

  it("shows the same clue on keyboard focus", async () => {
    render(
      <Tooltip label="Unpin thread">
        <button type="button">Action</button>
      </Tooltip>,
    );

    fireEvent.focus(screen.getByRole("button"));

    expect((await screen.findByRole("tooltip")).textContent).toBe(
      "Unpin thread",
    );
  });
});
