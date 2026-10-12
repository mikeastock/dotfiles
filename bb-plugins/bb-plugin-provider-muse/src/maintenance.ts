import { readFile } from "node:fs/promises";
import {
  experimental_clampPercent as clampPercent,
  experimental_commandOutput as commandOutput,
  experimental_compareVersions as compareVersions,
  experimental_downloadedInstallerCommand as downloadedInstallerCommand,
  experimental_installationVerification as installationVerification,
  experimental_resolveExecutablePath as resolveExecutablePath,
  experimental_versionFrom as versionFrom,
  type ProviderHealthResult,
  type ProviderInstallationRunResult,
  type ProviderInstallationStatus,
  type ProviderUsageResult,
} from "@get-bb/plugin-sdk/provider-bridge";
import { z } from "zod";
import {
  museAuthFilePath,
  museExecutable,
  museSessionsDir,
} from "./msp/paths.js";
import {
  museUsageWindows,
  type MuseSubscriptionUsage,
} from "./subscription-usage.js";
import {
  rollingWindowResetsAt,
  scanMuseUsage,
} from "./usage-scan.js";
import {
  MUSE_INSTALL_COMMAND,
  MUSE_INSTALL_SCRIPT_URL,
  MUSE_LOGIN_COMMAND,
  MUSE_MINIMUM_SUPPORTED_VERSION,
  MUSE_USAGE_WINDOW_HOURS,
} from "./vocabulary.js";

const HOUR_MS = 60 * 60 * 1_000;

const museAuthProviderSchema = z
  .object({
    mechanism: z.string().optional(),
    storage: z.string().optional(),
    obtained_via: z.string().optional(),
    api_base_url: z.string().optional(),
    user_email: z.string().optional(),
    user_full_name: z.string().optional(),
    plan: z.string().optional(),
    tier: z.string().optional(),
    expires_at: z.union([z.string(), z.number()]).optional(),
  })
  .loose();

const museAuthFileSchema = z
  .object({
    schema_version: z.number().optional(),
    providers: z.record(z.string(), museAuthProviderSchema).default({}),
  })
  .loose();

export type MuseAuthMechanism = "oauth" | "apiKey" | "unknown";

export interface MuseCredentials {
  mechanism: MuseAuthMechanism;
  accountEmail: string | null;
  planLabel: string | null;
  expired: boolean;
}

function mechanismOf(value: string | undefined): MuseAuthMechanism {
  if (value === "oauth") return "oauth";
  if (value === "api_key" || value === "apiKey") return "apiKey";
  return "unknown";
}

function expiresAtMs(value: string | number | undefined): number | null {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value > 1e12 ? value : value * 1_000;
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }
  return null;
}

export function credentialsFromAuthFile(
  raw: unknown,
  nowMs: number,
  env: NodeJS.ProcessEnv,
): MuseCredentials | null {
  const parsed = museAuthFileSchema.safeParse(raw);
  const meta = parsed.success ? parsed.data.providers.meta : undefined;
  const envKey = env.META_API_KEY;

  /**
   * `META_API_KEY` always takes priority over a stored account session, so a
   * host with the variable set is authenticated even when auth.json is absent.
   */
  if (envKey !== undefined && envKey !== "") {
    return {
      mechanism: "apiKey",
      accountEmail: meta?.user_email ?? null,
      planLabel: null,
      expired: false,
    };
  }
  if (meta === undefined) {
    return null;
  }
  const expiry = expiresAtMs(meta.expires_at);
  return {
    mechanism: mechanismOf(meta.mechanism),
    accountEmail: meta.user_email ?? null,
    planLabel: meta.plan ?? meta.tier ?? null,
    expired: expiry !== null && expiry <= nowMs,
  };
}

export async function readMuseCredentials(
  env: NodeJS.ProcessEnv = process.env,
  nowMs: number = Date.now(),
): Promise<MuseCredentials | null> {
  let raw: unknown = null;
  try {
    raw = JSON.parse(await readFile(museAuthFilePath(env), "utf8"));
  } catch {
    raw = null;
  }
  return credentialsFromAuthFile(raw, nowMs, env);
}

export async function readMuseVersion(
  env: NodeJS.ProcessEnv = process.env,
): Promise<string | null> {
  return versionFrom(await commandOutput(museExecutable(env), ["--version"]));
}

function healthResult(
  status:
    | "ready"
    | "not_installed"
    | "unauthenticated"
    | "expired"
    | "unsupported_version"
    | "unknown",
  args: {
    accountEmail?: string | null;
    planLabel?: string | null;
    installedVersion?: string | null;
    statusMessage?: string | null;
  } = {},
): ProviderHealthResult {
  return {
    supported: true,
    health: {
      status,
      statusMessage: args.statusMessage ?? null,
      accountEmail: args.accountEmail ?? null,
      planLabel: args.planLabel ?? null,
      installedVersion: args.installedVersion ?? null,
      minimumSupportedVersion: MUSE_MINIMUM_SUPPORTED_VERSION,
      canInstall: true,
      canUpdate: status !== "not_installed",
      loginCommand: MUSE_LOGIN_COMMAND,
    },
  };
}

export async function getMuseProviderHealth(
  env: NodeJS.ProcessEnv = process.env,
): Promise<ProviderHealthResult> {
  const executable = museExecutable(env);
  if ((await resolveExecutablePath(executable)) === null) {
    return healthResult("not_installed");
  }
  const version = await readMuseVersion(env);
  if (
    version !== null &&
    compareVersions(version, MUSE_MINIMUM_SUPPORTED_VERSION) < 0
  ) {
    return healthResult("unsupported_version", { installedVersion: version });
  }
  const credentials = await readMuseCredentials(env);
  if (credentials === null) {
    return healthResult("unauthenticated", { installedVersion: version });
  }
  if (credentials.expired) {
    return healthResult("expired", {
      accountEmail: credentials.accountEmail,
      installedVersion: version,
    });
  }
  return healthResult("ready", {
    accountEmail: credentials.accountEmail,
    planLabel: credentials.planLabel,
    installedVersion: version,
  });
}

export interface MuseUsageArgs {
  env?: NodeJS.ProcessEnv;
  nowMs?: number;
  tokenBudget?: number | null;
  planLabel?: string | null;
  /** The newest `usage/changed` reading any Muse host has reported. */
  subscription?: MuseSubscriptionUsage | null;
}

/**
 * Muse 1.4 reports the plan's own meters — the 5-hour block and the weekly
 * block, as Meta counts them — on every model response, and the bridge keeps
 * the newest one. That reading is the usage whenever one exists.
 *
 * Before the first Muse turn on this machine, or on a Muse build that predates
 * `usage/changed`, there is no reading. The window is then measured from
 * Muse's own session logs against a configured budget, and the plan's own
 * `resets_at` is used whenever the provider has actually refused a call for
 * quota. Without a budget there is no honest denominator, and the account is
 * shown with no window rather than an invented percentage.
 */
export async function getMuseProviderUsage(
  args: MuseUsageArgs = {},
): Promise<ProviderUsageResult> {
  const env = args.env ?? process.env;
  const nowMs = args.nowMs ?? Date.now();
  const executable = museExecutable(env);
  if ((await resolveExecutablePath(executable)) === null) {
    return { supported: true, usage: { status: "not_installed" } };
  }
  const credentials = await readMuseCredentials(env, nowMs);
  if (credentials === null) {
    return { supported: true, usage: { status: "unauthenticated" } };
  }
  if (credentials.expired) {
    return { supported: true, usage: { status: "expired" } };
  }

  const planLabel = args.planLabel ?? credentials.planLabel;
  if (args.subscription) {
    return {
      supported: true,
      usage: {
        status: "ok",
        accountEmail: credentials.accountEmail,
        planLabel,
        windows: museUsageWindows(args.subscription, nowMs),
      },
    };
  }
  const budget = args.tokenBudget ?? null;
  if (budget === null) {
    return {
      supported: true,
      usage: {
        status: "ok",
        accountEmail: credentials.accountEmail,
        planLabel,
        windows: [],
      },
    };
  }

  const windowMs = MUSE_USAGE_WINDOW_HOURS * HOUR_MS;
  try {
    const scan = await scanMuseUsage({
      sessionsDir: museSessionsDir(env),
      nowMs,
      windowMs,
    });
    const limited =
      scan.rateLimit !== null &&
      (scan.rateLimit.resetsAtMs === null || scan.rateLimit.resetsAtMs > nowMs);
    return {
      supported: true,
      usage: {
        status: "ok",
        accountEmail: credentials.accountEmail,
        planLabel,
        windows: [
          {
            label: `${MUSE_USAGE_WINDOW_HOURS}-hour limit`,
            usedPercent: limited
              ? 100
              : clampPercent((scan.windowTokens / budget) * 100),
            resetsAt:
              limited && scan.rateLimit?.resetsAtMs != null
                ? new Date(scan.rateLimit.resetsAtMs).toISOString()
                : rollingWindowResetsAt(scan, windowMs),
          },
        ],
      },
    };
  } catch (error) {
    return {
      supported: true,
      usage: {
        status: "error",
        message: error instanceof Error ? error.message : String(error),
        accountEmail: credentials.accountEmail,
        planLabel,
      },
    };
  }
}

export async function getMuseInstallationStatus(
  env: NodeJS.ProcessEnv = process.env,
): Promise<ProviderInstallationStatus> {
  const executableName = museExecutable(env);
  const [executablePath, version] = await Promise.all([
    resolveExecutablePath(executableName),
    readMuseVersion(env),
  ]);
  const installed = executablePath !== null || version !== null;
  const versionUnsupported =
    installed &&
    version !== null &&
    compareVersions(version, MUSE_MINIMUM_SUPPORTED_VERSION) < 0;
  const actionKind = !installed ? "install" : versionUnsupported ? "update" : null;

  return {
    executableName,
    executablePath,
    installed,
    /**
     * Muse ships a self-updating launcher from Meta's own channel rather than a
     * package registry, so nothing here is npm-shaped.
     */
    installSource: installed ? "external" : "notInstalled",
    currentVersion: version,
    latestVersion: null,
    minimumSupportedVersion: MUSE_MINIMUM_SUPPORTED_VERSION,
    npmPackageName: null,
    npmGlobalPackageVersion: null,
    installAction:
      actionKind === null
        ? null
        : {
            kind: actionKind,
            label: actionKind === "install" ? "Install" : "Update",
            command: MUSE_INSTALL_COMMAND,
          },
    needsUpdate: false,
    versionUnsupported,
  };
}

export async function getMuseInstallationRun(
  action: "install" | "update",
  env: NodeJS.ProcessEnv = process.env,
): Promise<ProviderInstallationRunResult> {
  const status = await getMuseInstallationStatus(env);
  return buildMuseInstallationRun(status, action);
}

export function buildMuseInstallationRun(
  status: ProviderInstallationStatus,
  action: "install" | "update",
): ProviderInstallationRunResult {
  if (status.installAction?.kind !== action) {
    return {
      available: false,
      message: `Muse ${action} is not available on this host.`,
    };
  }
  return {
    available: true,
    command: downloadedInstallerCommand(MUSE_INSTALL_SCRIPT_URL),
    verification: installationVerification(status, action),
  };
}
