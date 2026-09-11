import { useState } from "react";
import { cn } from "./lib/utils";

const loadedSources = new Set<string>();
const failedSources = new Set<string>();

export function ProjectFavicon({
  src,
  className,
}: {
  src: string | null;
  className?: string;
}) {
  const [loadedSrc, setLoadedSrc] = useState<string | null>(() =>
    src && loadedSources.has(src) ? src : null,
  );
  const [failedSrc, setFailedSrc] = useState<string | null>(() =>
    src && failedSources.has(src) ? src : null,
  );
  if (!src || failedSrc === src || failedSources.has(src)) return null;

  if (loadedSrc === src || loadedSources.has(src)) {
    return (
      <img
        src={src}
        alt=""
        className={cn("size-3.5 shrink-0 rounded-sm object-contain", className)}
        onError={() => {
          loadedSources.delete(src);
          failedSources.add(src);
          setFailedSrc(src);
        }}
      />
    );
  }

  return (
    <span aria-hidden="true" className={cn("size-3.5 shrink-0", className)}>
      <img
        src={src}
        alt=""
        className="hidden"
        onLoad={() => {
          failedSources.delete(src);
          loadedSources.add(src);
          setLoadedSrc(src);
        }}
        onError={() => {
          failedSources.add(src);
          setFailedSrc(src);
        }}
      />
    </span>
  );
}
