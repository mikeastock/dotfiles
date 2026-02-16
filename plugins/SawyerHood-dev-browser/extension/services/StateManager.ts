/**
 * StateManager - Manages extension active/inactive state with persistence.
 */

const STORAGE_KEY = "devBrowserActiveState";

export interface ExtensionState {
  isActive: boolean;
}

export class StateManager {
  /**
   * Get the current extension state.
   * Defaults to inactive if no state is stored.
   */
  async getState(): Promise<ExtensionState> {
    const result = await chrome.storage.local.get(STORAGE_KEY);
    const state = result[STORAGE_KEY] as ExtensionState | undefined;
    return state ?? { isActive: false };
  }

  /**
   * Set the extension state.
   */
  async setState(state: ExtensionState): Promise<void> {
    await chrome.storage.local.set({ [STORAGE_KEY]: state });
  }
}
