import { useEffect, useState, type ReactNode } from "react";
import { cn } from "./lib/utils";

// Keyed by the icon route URL. A loaded entry holds the attempt URL that
// succeeded. A failure is retried with backoff instead of blocking the icon
// until reload: the first request can fail while bb's host is still starting.
const loadedSources = new Map<string, string>();
const failedSources = new Map<string, { count: number; retryAt: number }>();
const RETRY_BASE_MS = 15_000;
const RETRY_MAX_MS = 10 * 60_000;

function attemptUrl(src: string, attempt: number): string {
  if (attempt === 0) return src;
  return `${src}${src.includes("?") ? "&" : "?"}attempt=${attempt}`;
}

function recordFailure(src: string, attempt: number): void {
  // Every row showing this project sees the same failed request; count it once.
  if ((failedSources.get(src)?.count ?? 0) !== attempt) return;
  const count = attempt + 1;
  failedSources.set(src, {
    count,
    retryAt:
      Date.now() + Math.min(RETRY_BASE_MS * 2 ** (count - 1), RETRY_MAX_MS),
  });
}

export function ProjectFavicon({
  src,
  className,
  fallback = null,
}: {
  src: string | null;
  className?: string;
  fallback?: ReactNode;
}) {
  const [, setRenderCount] = useState(0);
  const rerender = () => setRenderCount((count) => count + 1);
  const failure = src ? failedSources.get(src) : undefined;
  const retryAt =
    failure && failure.retryAt > Date.now() ? failure.retryAt : null;
  useEffect(() => {
    if (retryAt === null) return;
    const timer = setTimeout(rerender, retryAt - Date.now());
    return () => clearTimeout(timer);
  }, [src, retryAt]);
  if (!src || retryAt !== null) return fallback;

  const loadedUrl = loadedSources.get(src);
  if (loadedUrl) {
    return (
      <img
        src={loadedUrl}
        alt=""
        className={cn("size-3.5 shrink-0 rounded-sm object-contain", className)}
        onError={() => {
          loadedSources.delete(src);
          recordFailure(src, 0);
          rerender();
        }}
      />
    );
  }

  const attempt = failure?.count ?? 0;
  const url = attemptUrl(src, attempt);
  return (
    <span aria-hidden="true" className={cn("size-3.5 shrink-0", className)}>
      {fallback}
      <img
        src={url}
        alt=""
        className="hidden"
        onLoad={() => {
          failedSources.delete(src);
          loadedSources.set(src, url);
          rerender();
        }}
        onError={() => {
          recordFailure(src, attempt);
          rerender();
        }}
      />
    </span>
  );
}
