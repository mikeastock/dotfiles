import { homedir } from "node:os";
import { join } from "node:path";
import { MUSE_DEFAULT_EXECUTABLE, MUSE_EXECUTABLE_ENV, MUSE_HOME_ENV } from "../vocabulary.js";

/**
 * Muse follows the XDG layout on every platform it ships for: configuration in
 * `~/.config/muse`, durable session logs in `~/.local/share/muse`. `MUSE_HOME`
 * relocates both, and the MSP handshake reports the effective home so a bridge
 * never has to guess for a session it opened.
 */
export function museConfigDir(env: NodeJS.ProcessEnv = process.env): string {
  const overridden = env[MUSE_HOME_ENV];
  if (overridden !== undefined && overridden !== "") {
    return join(overridden, "config");
  }
  const xdgConfig = env.XDG_CONFIG_HOME;
  if (xdgConfig !== undefined && xdgConfig !== "") {
    return join(xdgConfig, "muse");
  }
  return join(homedir(), ".config", "muse");
}

export function museDataDir(env: NodeJS.ProcessEnv = process.env): string {
  const overridden = env[MUSE_HOME_ENV];
  if (overridden !== undefined && overridden !== "") {
    return join(overridden, "data");
  }
  const xdgData = env.XDG_DATA_HOME;
  if (xdgData !== undefined && xdgData !== "") {
    return join(xdgData, "muse");
  }
  return join(homedir(), ".local", "share", "muse");
}

export function museAuthFilePath(env: NodeJS.ProcessEnv = process.env): string {
  return join(museConfigDir(env), "auth.json");
}

export function museSettingsFilePath(
  env: NodeJS.ProcessEnv = process.env,
): string {
  return join(museConfigDir(env), "settings.json");
}

export function museSessionsDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(museDataDir(env), "sessions");
}

export function museExecutable(env: NodeJS.ProcessEnv = process.env): string {
  const overridden = env[MUSE_EXECUTABLE_ENV];
  return overridden !== undefined && overridden !== ""
    ? overridden
    : MUSE_DEFAULT_EXECUTABLE;
}
