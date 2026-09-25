/** Match BB's own runtime, never all descendants of a BB process. */
export function isBbInternalListener(processName: string, command = ""): boolean {
  // BB host/provider workers can run under node or the desktop executable.
  if (/[/\\]bb-app[/\\](?:host-daemon|server)[/\\]dist[/\\]/.test(command)) return true;
  if (/[/\\]bb-(?:provider-bridge|plugin-host)-worker\.mjs(?:\s|$)/.test(command)) return true;

  const bbName = /^bb(?: nightly| beta| helper(?: \([^)]+\))?)?$/i.test(processName);
  if (!bbName) return false;
  if (!command) return true;
  // A BB executable running a workspace script is still a user server.
  const executable = command.match(/^.*?[/\\]Contents[/\\]MacOS[/\\]bb(?: Nightly| Beta)?(?=\s|$)/i)?.[0];
  const args = executable ? command.slice(executable.length).trim() : command.replace(/^\S+\s*/, "").trim();
  return !args || args.startsWith("--type=");
}

export function parseProcessCommands(output: string): Map<number, string> {
  const commands = new Map<number, string>();
  for (const line of output.split("\n")) {
    const match = line.match(/^\s*(\d+)\s+(.+)$/);
    if (match) commands.set(Number(match[1]), match[2]);
  }
  return commands;
}
