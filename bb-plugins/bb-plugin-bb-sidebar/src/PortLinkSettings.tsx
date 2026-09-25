import { useSyncExternalStore } from "react";
import { experimental_useSidebarThreads as useSidebarThreads } from "@get-bb/plugin-sdk/app";
import { safeSetItem } from "./lib/safe-storage";

export const PORT_LINK_HOST_KEY = "bb-sidebar:port-link-host:v1";
const CHANGE = "bb-sidebar:port-link-host-changed";
function subscribe(listener: () => void) {
  window.addEventListener("storage", listener);
  window.addEventListener(CHANGE, listener);
  return () => {
    window.removeEventListener("storage", listener);
    window.removeEventListener(CHANGE, listener);
  };
}
function readHost() {
  try { return window.localStorage.getItem(PORT_LINK_HOST_KEY) || null; } catch { return null; }
}
export function usePortLinkHost() {
  return useSyncExternalStore(subscribe, readHost, () => null);
}
export function PortLinkSettings() {
  const hostId = usePortLinkHost();
  const { threads } = useSidebarThreads();
  const hosts = new Map(threads.flatMap((thread) => thread.host ? [[thread.host.id, thread.host.name] as const] : []));
  return (
    <section className="space-y-2">
      <label htmlFor="port-link-host" className="block text-sm font-semibold text-foreground">Port links on this device</label>
      <p className="text-xs leading-5 text-muted-foreground">Choose the machine where this browser opens pages. Ports on other machines stay as text. Saved only on this device.</p>
      <select id="port-link-host" value={hostId ?? ""} onChange={(event) => {
        safeSetItem(PORT_LINK_HOST_KEY, event.target.value);
        window.dispatchEvent(new Event(CHANGE));
      }} className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground">
        <option value="">Do not open local port links</option>
        {hostId && !hosts.has(hostId) ? <option value={hostId}>Previously selected machine</option> : null}
        {[...hosts].map(([id, name]) => <option key={id} value={id}>{name}</option>)}
      </select>
      <p className="text-xs text-muted-foreground">Links try HTTP, or HTTPS on ports 443 and 8443. Known database and non-web service ports are not linked.</p>
    </section>
  );
}
