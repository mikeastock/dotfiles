import { describe, it, expect, beforeEach } from "vitest";
import { fakeBrowser } from "wxt/testing";
import { StateManager } from "../services/StateManager";

describe("StateManager", () => {
  let stateManager: StateManager;

  beforeEach(() => {
    fakeBrowser.reset();
    stateManager = new StateManager();
  });

  describe("getState", () => {
    it("should return default inactive state when no stored state", async () => {
      const state = await stateManager.getState();
      expect(state).toEqual({ isActive: false });
    });

    it("should return stored state when available", async () => {
      await fakeBrowser.storage.local.set({
        devBrowserActiveState: { isActive: true },
      });

      const state = await stateManager.getState();
      expect(state).toEqual({ isActive: true });
    });
  });

  describe("setState", () => {
    it("should persist state to storage", async () => {
      await stateManager.setState({ isActive: true });

      const stored = await fakeBrowser.storage.local.get("devBrowserActiveState");
      expect(stored.devBrowserActiveState).toEqual({ isActive: true });
    });

    it("should update state from active to inactive", async () => {
      await stateManager.setState({ isActive: true });
      await stateManager.setState({ isActive: false });

      const state = await stateManager.getState();
      expect(state).toEqual({ isActive: false });
    });
  });
});
