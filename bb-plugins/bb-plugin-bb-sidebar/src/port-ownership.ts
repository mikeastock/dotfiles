/** Extract only BB's thread marker. Never return or log process environments. */
export function threadIdFromEnvironment(environment: string, separator: "nul" | "space"): string | undefined {
  const entries = separator === "nul" ? environment.split("\0") : environment.split(/\s+/);
  const values = entries.filter((entry) => entry.startsWith("BB_THREAD_ID="));
  if (values.length !== 1) return undefined;
  const value = values[0].slice("BB_THREAD_ID=".length);
  return /^thr_[a-zA-Z0-9_-]+$/.test(value) ? value : undefined;
}

export function macProcessEnvironment(command: string, commandWithEnvironment: string): string {
  const prefix = command.trim();
  const full = commandWithEnvironment.trim();
  // A process that exited or changed commands between reads stays unassigned.
  return prefix && full.startsWith(`${prefix} `) ? full.slice(prefix.length + 1) : "";
}
