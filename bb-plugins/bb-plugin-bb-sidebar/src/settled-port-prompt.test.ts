import { beforeEach, describe, expect, it, vi } from "vitest";
import { promptToCloseSettledPorts } from "./settled-port-prompt";

const toast = vi.hoisted(() => ({ message: vi.fn(), success: vi.fn(), error: vi.fn() }));
vi.mock("sonner", () => ({ toast }));
const ports = [{ port: 3000, pid: 123 }];
const getPorts = async () => ({ ports });
const current = () => true;

describe("settled port prompt", () => {
  beforeEach(() => vi.clearAllMocks());

  it("asks before closing, and Keep open leaves the processes alone", async () => {
    const close = vi.fn();
    await promptToCloseSettledPorts("thr_a", getPorts, close, current);
    const options = toast.message.mock.calls[0][1];
    expect(options.description).toContain(":3000");
    expect(options.duration).toBe(Infinity);
    expect(close).not.toHaveBeenCalled();
    options.cancel.onClick();
    expect(close).not.toHaveBeenCalled();
  });

  it("closes only the confirmed snapshot, once", async () => {
    const close = vi.fn().mockResolvedValue({ signalled: [3000], skipped: [], failed: [] });
    await promptToCloseSettledPorts("thr_a", getPorts, close, current);
    const options = toast.message.mock.calls[0][1];
    await options.action.onClick();
    await options.action.onClick();
    expect(close.mock.calls).toEqual([[ports]]);
    expect(toast.success).toHaveBeenCalled();
  });

  it("does not prompt for no ports or a settle that was undone", async () => {
    const close = vi.fn();
    await promptToCloseSettledPorts("thr_a", async () => ({ ports: [] }), close, current);
    await promptToCloseSettledPorts("thr_a", getPorts, close, () => false);
    expect(toast.message).not.toHaveBeenCalled();
  });

  it("ignores a pending confirmation after Undo", async () => {
    let valid = true;
    const close = vi.fn();
    await promptToCloseSettledPorts("thr_a", getPorts, close, () => valid);
    valid = false;
    await toast.message.mock.calls[0][1].action.onClick();
    expect(close).not.toHaveBeenCalled();
  });

  it("reports failed shutdowns without claiming the ports closed", async () => {
    const close = vi.fn().mockResolvedValue({ signalled: [], skipped: [], failed: [3000] });
    await promptToCloseSettledPorts("thr_a", getPorts, close, current);
    await toast.message.mock.calls[0][1].action.onClick();
    expect(toast.error).toHaveBeenCalledWith("Some port processes could not be stopped", { description: ":3000" });
    expect(toast.success).not.toHaveBeenCalled();
  });
});
