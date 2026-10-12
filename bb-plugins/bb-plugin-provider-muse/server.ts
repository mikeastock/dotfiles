import type { BbPluginApi } from "@get-bb/plugin-sdk";
import {
  MUSE_ICON_GLYPH,
  MUSE_REASONING_LEVELS,
  MUSE_INSTALL_URL,
  MUSE_LOGIN_COMMAND,
  MUSE_PROVIDER_ID,
  MUSE_USAGE_WINDOW_HOURS,
  museExtensionKinds,
  type MuseProviderOptions,
} from "./src/vocabulary.js";

/**
 * Settings values arrive as strings, and a budget is easier to paste as
 * "12_000_000" or "12000000" than to retype exactly, so separators are ignored.
 */
export function parseTokenBudget(value: unknown): number | null {
  if (typeof value !== "string") {
    return null;
  }
  const digits = value.replace(/[\s_,]/gu, "");
  if (!/^\d+$/u.test(digits)) {
    return null;
  }
  const parsed = Number.parseInt(digits, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function nonEmptyStringOrNull(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

export default function plugin(bb: BbPluginApi) {
  bb.settings.define({
    windowTokenBudget: {
      type: "string",
      label: `Rolling ${MUSE_USAGE_WINDOW_HOURS}-hour token budget`,
      description:
        "Only used before Muse reports your plan's own meters. Muse 1.4 and later sends the real 5-hour and weekly usage with every model response, and BB shows those as soon as one Muse turn has run. Until then — or on an older Muse — BB measures the window from Muse's session logs against this many tokens. Leave empty to show no meter until Muse reports one.",
      default: "",
    },
    planLabel: {
      type: "string",
      label: "Plan label",
      description:
        "How your Muse subscription is shown in usage surfaces, for example \"High usage\".",
      default: "",
    },
    trustWorkspace: {
      type: "boolean",
      label: "Load workspace skills and rules",
      description:
        "Start Muse sessions with the workspace trusted so its AGENTS.md, skills, and rules load.",
      default: true,
    },
    sandbox: {
      type: "select",
      label: "Muse's own OS sandbox",
      description:
        "OFF BY DEFAULT — commands Muse runs are not confined by Muse's own OS sandbox, and BB's permission modes and approvals are the only enforcement surface. The default is off because Muse's sandbox is all-or-nothing and denies the Darwin per-user cache, so with it on no Swift or Clang compilation works: a two-line file fails to build. Turn it on for OS-level containment if your work needs no native toolchain. BB's Full access permission mode disables it either way.",
      options: ["off", "on"],
      default: "off",
    },
    sandboxNetwork: {
      type: "select",
      label: "Sandbox network",
      description:
        "NETWORK IS ALLOWED BY DEFAULT for sandboxed Muse shell commands. Muse's own default, proxy-only, truncates larger loopback responses and breaks the `bb` CLI that BB tells agents to use, so BB threads allow it. Choose proxy-only or restricted to narrow it. Applies only while Muse's OS sandbox is on, and is fixed for the lifetime of a Muse host process.",
      options: ["enabled", "proxy-only", "restricted"],
      default: "enabled",
    },
  });

  bb.providers.register({
    id: MUSE_PROVIDER_ID,
    displayName: "Muse Code",
    icon: MUSE_ICON_GLYPH,
    family: "muse",
    strings: {
      signInHint: `Run \`${MUSE_LOGIN_COMMAND}\` on the machine to sign in.`,
      expiredHint: `Your Muse Code session expired. Run \`${MUSE_LOGIN_COMMAND}\`, then reload.`,
      installUrl: MUSE_INSTALL_URL,
      brandPrefix: "Muse ",
      iconTint: { light: "#1d4ed8", dark: "#93c5fd" },
    },
    experimental_visibility: "installed",
    models: { scope: "host" },
    maintenance: { health: true, usage: true, installation: true },
    capabilities: {
      supportsServiceTier: false,
      supportsNativeUserQuestion: true,
      fork: "tip",
      supportsManualCompaction: true,
      supportsThreadArchive: false,
      supportsThreadRename: false,
      permissionModes: ["accept-edits", "auto", "full"],
      reasoningLevels: [...MUSE_REASONING_LEVELS],
    },
    reasoningLevels: [
      { id: "low", label: "Low" },
      { id: "medium", label: "Medium" },
      { id: "high", label: "High", description: "Muse Code's own default." },
      { id: "xhigh", label: "X-High" },
      { id: "max", label: "Max", description: "Muse's native max effort." },
      { id: "ultra", label: "Ultra", description: "Muse's native ultra effort." },
    ],
    composerActions: [],
    env: { passthrough: ["BB_MUSE_EXECUTABLE", "MUSE_HOME", "META_API_KEY"] },
    extensionKinds: museExtensionKinds,
    deriveProviderOptions(context): MuseProviderOptions {
      return {
        trustWorkspace: context.settings.trustWorkspace !== false,
        sandbox: context.settings.sandbox === "on" ? "on" : "off",
        sandboxNetwork:
          context.settings.sandboxNetwork === "proxy-only"
            ? "proxy-only"
            : context.settings.sandboxNetwork === "restricted"
              ? "restricted"
              : "enabled",
        tokenBudget: parseTokenBudget(context.settings.windowTokenBudget),
        planLabel: nonEmptyStringOrNull(context.settings.planLabel),
      };
    },
  });
}
