import type { BbPluginApi, PluginHttpHandler } from "@get-bb/plugin-sdk";
import { PLANNOTATOR_RELAY_PATH } from "./constants";

/** The single BB route used when the browser can only reach BB's origin. */
export const PLANNOTATOR_RELAY_ROUTE = "/review";

const MAX_UPSTREAM_PATH_LENGTH = 16_384;
const HOP_BY_HOP_HEADERS = [
  "connection",
  "content-encoding",
  "content-length",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
];

type RelaySessionMap = Map<string, string>;
type RelayContext = Parameters<PluginHttpHandler>[0];
type FetchLike = typeof fetch;

export function buildPlannotatorRelayUrl(
  relayPath: string,
  sessionId: string,
  upstreamPath = "/",
  origin?: string,
): string {
  const base = origin ?? "http://bb.invalid";
  const url = new URL(relayPath, base);
  url.searchParams.set("sessionId", sessionId);
  url.searchParams.set("path", upstreamPath);
  return origin ? url.toString() : `${url.pathname}${url.search}`;
}

export function isSafeUpstreamPath(path: string): boolean {
  return (
    path.length > 0 &&
    path.length <= MAX_UPSTREAM_PATH_LENGTH &&
    path.startsWith("/") &&
    !path.startsWith("//") &&
    !path.includes("\\") &&
    !path.includes("\u0000") &&
    !path.includes("#")
  );
}

function relayLocation(
  value: string,
  upstreamBaseUrl: string,
  relayPath: string,
  sessionId: string,
): string {
  try {
    const base = new URL(upstreamBaseUrl);
    const location = new URL(value, base);
    if (location.origin !== base.origin) return value;
    return buildPlannotatorRelayUrl(
      relayPath,
      sessionId,
      `${location.pathname}${location.search}`,
    );
  } catch {
    return value;
  }
}

function copyResponseHeaders(
  response: Response,
  options: {
    upstreamBaseUrl: string;
    relayPath: string;
    sessionId: string;
    html: boolean;
  },
): Headers {
  const headers = new Headers(response.headers);
  for (const header of HOP_BY_HOP_HEADERS) headers.delete(header);
  if (options.html) {
    // The embedded document is served by BB's origin and receives our inline
    // transport bootstrap. Upstream CSP/frame headers would otherwise block
    // the intentionally thin embedding adapter.
    headers.delete("content-security-policy");
    headers.delete("content-security-policy-report-only");
    headers.delete("x-frame-options");
  }
  const location = headers.get("location");
  if (location) {
    headers.set(
      "location",
      relayLocation(
        location,
        options.upstreamBaseUrl,
        options.relayPath,
        options.sessionId,
      ),
    );
  }
  return headers;
}

function errorResponse(message: string, status: number): Response {
  return new Response(message, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

function buildUpstreamUrl(baseUrl: string, path: string): string | null {
  if (!isSafeUpstreamPath(path)) return null;
  try {
    const base = new URL(baseUrl);
    if (base.protocol !== "http:" && base.protocol !== "https:") return null;
    const target = new URL(path, base);
    if (target.origin !== base.origin) return null;
    return target.toString();
  } catch {
    return null;
  }
}

function isHtmlResponse(response: Response): boolean {
  return (response.headers.get("content-type") ?? "")
    .toLowerCase()
    .includes("text/html");
}

/**
 * Add transport only. The upstream app still owns the complete document and
 * all review behavior; this script keeps its root-relative requests on BB's
 * one remotely published origin.
 */
export function injectRelayBootstrap(
  html: string,
  relayPath: string,
  sessionId: string,
): string {
  const script = `<script data-bb-plannotator-relay>
(() => {
  "use strict";
  const relayPath = ${JSON.stringify(relayPath)};
  const sessionId = ${JSON.stringify(sessionId)};

  const rewrite = (value) => {
    if (typeof value !== "string") return value;
    let url;
    try {
      url = new URL(value, window.location.href);
    } catch {
      return value;
    }
    if (url.origin !== window.location.origin || !url.pathname.startsWith("/")) {
      return value;
    }
    if (url.pathname === relayPath || url.pathname.startsWith(relayPath + "/")) {
      return value;
    }
    const relay = new URL(relayPath, window.location.href);
    relay.searchParams.set("sessionId", sessionId);
    relay.searchParams.set("path", url.pathname + url.search);
    return relay.toString();
  };

  const nativeFetch = window.fetch.bind(window);
  window.fetch = (input, init) => {
    if (input instanceof Request) {
      return nativeFetch(new Request(rewrite(input.url), input), init);
    }
    return nativeFetch(rewrite(String(input)), init);
  };

  try {
    const nativeOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(...args) {
      args[1] = rewrite(String(args[1]));
      return nativeOpen.apply(this, args);
    };
  } catch {}

  try {
    const NativeEventSource = window.EventSource;
    const RelayEventSource = function(url, config) {
      return new NativeEventSource(rewrite(String(url)), config);
    };
    RelayEventSource.prototype = NativeEventSource.prototype;
    window.EventSource = RelayEventSource;
  } catch {}

  const rewriteElement = (element) => {
    for (const attribute of ["src", "href", "action"]) {
      const value = element.getAttribute?.(attribute);
      if (value && value.startsWith("/") && !value.startsWith("//")) {
        element.setAttribute(attribute, rewrite(value));
      }
    }
  };
  const scan = () => {
    document.querySelectorAll("[src], [href], [action]").forEach(rewriteElement);
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scan, { once: true });
  } else {
    scan();
  }
  try {
    new MutationObserver((records) => {
      for (const record of records) {
        for (const node of record.addedNodes) {
          if (node.nodeType === Node.ELEMENT_NODE) rewriteElement(node);
        }
      }
    }).observe(document.documentElement, { childList: true, subtree: true });
  } catch {}
})();
</script>`;
  // Do not search for the first closing </head>. The upstream bundle is an
  // inline script and contains HTML template strings such as `</head>`; an
  // index-based insertion at that occurrence corrupts the module before the
  // browser can execute it. Place the bootstrap immediately after the real
  // opening head tag, before the deferred upstream module starts.
  const headStart = html.match(/<head\b[^>]*>/iu);
  if (!headStart || headStart.index === undefined) return `${script}${html}`;
  const insertAt = headStart.index + headStart[0].length;
  return `${html.slice(0, insertAt)}${script}${html.slice(insertAt)}`;
}

export function createPlannotatorRelayHandler(
  sessions: RelaySessionMap,
  relayPath = PLANNOTATOR_RELAY_PATH,
  fetchImpl: FetchLike = fetch,
): PluginHttpHandler {
  return async (context: RelayContext) => {
    const sessionId = context.req.query("sessionId")?.trim() ?? "";
    const path = context.req.query("path") ?? "/";
    const upstreamBaseUrl = sessions.get(sessionId);
    if (!sessionId || !upstreamBaseUrl) {
      return errorResponse("Unknown or expired Plannotator session", 404);
    }

    const targetUrl = buildUpstreamUrl(upstreamBaseUrl, path);
    if (!targetUrl) return errorResponse("Invalid Plannotator path", 400);

    const request = context.req.raw;
    const requestHeaders = new Headers(request.headers);
    for (const header of [
      "connection",
      "content-length",
      "host",
      "origin",
      "referer",
      "transfer-encoding",
      "x-forwarded-host",
      "x-forwarded-proto",
    ]) {
      requestHeaders.delete(header);
    }
    requestHeaders.set("accept-encoding", "identity");

    let body: ArrayBuffer | undefined;
    if (request.method !== "GET" && request.method !== "HEAD") {
      body = await request.arrayBuffer();
    }

    let upstreamResponse: Response;
    try {
      upstreamResponse = await fetchImpl(targetUrl, {
        method: request.method,
        headers: requestHeaders,
        body: body && body.byteLength > 0 ? body : undefined,
        redirect: "manual",
      });
    } catch (error) {
      return errorResponse(
        `Plannotator upstream unavailable: ${
          error instanceof Error ? error.message : String(error)
        }`,
        502,
      );
    }

    const html = isHtmlResponse(upstreamResponse);
    const headers = copyResponseHeaders(upstreamResponse, {
      upstreamBaseUrl,
      relayPath,
      sessionId,
      html,
    });

    if (html && request.method !== "HEAD") {
      const document = await upstreamResponse.text();
      const embedded = injectRelayBootstrap(document, relayPath, sessionId);
      return new Response(embedded, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers,
      });
    }

    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers,
    });
  };
}

export function registerPlannotatorRelayRoutes(
  bb: BbPluginApi,
  sessions: RelaySessionMap,
): void {
  const handler = createPlannotatorRelayHandler(sessions);
  for (const method of [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
  ]) {
    // The random session capability is the auth boundary. BB's local auth
    // intentionally rejects a Tailscale Host/Origin, while token auth would
    // require the remote browser to know a plugin secret.
    bb.http.route(method, PLANNOTATOR_RELAY_ROUTE, handler, { auth: "none" });
  }
}
