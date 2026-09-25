import type { OpenPort } from "./open-ports";

const NON_WEB_PORTS = new Set([22, 25, 53, 110, 143, 389, 465, 587, 636, 993, 995, 1433, 1521, 3306, 5432, 5672, 6379, 9042, 11211, 27017]);

/** Only offer local browser navigation when the user has identified this device. */
export function portBrowserUrl(port: OpenPort, hostId: string | undefined, localHostId: string | null): string | null {
  if (!hostId || hostId !== localHostId) return null;
  if (NON_WEB_PORTS.has(port.port) || /postgres|mysqld|mariadb|redis|mongod|memcached/i.test(`${port.processName ?? ""} ${port.service ?? ""}`)) return null;
  let address = port.address ?? "127.0.0.1";
  if (["*", "0.0.0.0"].includes(address)) address = "127.0.0.1";
  if (address === "::") address = "::1";
  // The scanner emits IP addresses, never arbitrary URLs or credentials.
  if (!/^[\da-fA-F:.]+$/.test(address)) return null;
  const hostname = address.includes(":") ? `[${address}]` : address;
  const scheme = port.port === 443 || port.port === 8443 ? "https" : "http";
  return `${scheme}://${hostname}:${port.port}/`;
}
