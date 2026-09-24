export const SIDEBAR_SETTINGS_CHANNEL = "sidebar-settings";

export interface SidebarSettingsValues {
  snoozePresets: string;
  inactiveThreadsEnabled: boolean;
  inactiveAfterHours: number;
  autoSettleInactive: boolean;
  autoSettleAfterDays: number;
  autoSettleOnMerge: boolean;
}

export const DEFAULT_SIDEBAR_SETTINGS: SidebarSettingsValues = {
  snoozePresets: "30m, 2h, 1d, 1w",
  inactiveThreadsEnabled: true,
  inactiveAfterHours: 6,
  autoSettleInactive: true,
  autoSettleAfterDays: 3,
  autoSettleOnMerge: true,
};

const SIDEBAR_SETTINGS_CACHE_KEY = "bb-sidebar:settings-cache:v1";
const settingsByRpcClient = new WeakMap<object, SidebarSettingsValues>();

function readStoredSidebarSettings(): SidebarSettingsValues | null {
  try {
    const stored = window.localStorage.getItem(SIDEBAR_SETTINGS_CACHE_KEY);
    if (!stored) return null;
    const value = JSON.parse(stored) as Partial<SidebarSettingsValues>;
    if (
      typeof value.snoozePresets !== "string" ||
      typeof value.inactiveThreadsEnabled !== "boolean" ||
      typeof value.inactiveAfterHours !== "number" ||
      typeof value.autoSettleInactive !== "boolean" ||
      typeof value.autoSettleAfterDays !== "number" ||
      typeof value.autoSettleOnMerge !== "boolean"
    ) {
      return null;
    }
    return value as SidebarSettingsValues;
  } catch {
    return null;
  }
}

export function cachedSidebarSettings(
  rpcClient: object,
): SidebarSettingsValues | null {
  const cached = settingsByRpcClient.get(rpcClient);
  if (cached) return cached;
  const stored = readStoredSidebarSettings();
  if (stored) settingsByRpcClient.set(rpcClient, stored);
  return stored;
}

export function cacheSidebarSettings(
  rpcClient: object,
  values: SidebarSettingsValues,
): SidebarSettingsValues {
  settingsByRpcClient.set(rpcClient, values);
  try {
    window.localStorage.setItem(
      SIDEBAR_SETTINGS_CACHE_KEY,
      JSON.stringify(values),
    );
  } catch {
    // A hardened browser can disable storage. The in-memory cache still
    // prevents flicker while this app runtime remains open.
  }
  return values;
}
