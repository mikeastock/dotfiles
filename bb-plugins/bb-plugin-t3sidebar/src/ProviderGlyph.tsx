import { cn } from "./lib/utils";
import { TRAILING_GLYPH_BOX_CLASS } from "./StatusSlot";

type ProviderArt = {
  /** Accessible name, matching what `bb provider list` calls the provider. */
  label: string;
  viewBox: string;
  /** Path `d` strings, drawn in order and filled with `currentColor`. */
  paths: string[];
  /** Only for artwork whose holes are cut by overlapping subpaths. */
  fillRule?: "evenodd";
};

/**
 * Artwork per provider id, lifted from bb's own provider icons so a card reads
 * the same as the thread it points at.
 *
 * Keyed by the ids `bb provider list` reports, which is why the ACP-backed
 * agents carry their `acp-` prefix. Providers absent from this table are drawn
 * as a neutral dot, so a new agent degrades quietly instead of vanishing.
 */
const PROVIDER_ART: Record<string, ProviderArt> = {
  "claude-code": {
    label: "Claude Code",
    viewBox: "0 0 149 149",
    paths: [
      "M29 98.5 58.2 82.2l.5-1.4-.5-.8h-1.4l-4.9-.3-16.6-.5-14.5-.6-14-.7-3.5-.8L0 72.8l.3-2.2 3-2 4.2.4 9.4.6 14 1 10.2.6 15.1 1.6h2.4l.3-1-.8-.6-.6-.6-14.6-9.9-15.7-10.4-8.3-6-4.4-3-2.3-2.9-1-6.2 4.1-4.5 5.4.4 1.4.4 5.5 4.2 11.8 9.1 15.3 11.3 2.3 1.9.9-.7.1-.4-1-1.7-8.3-15.1-8.9-15.4-4-6.3-1-3.9c-.4-1.5-.7-2.9-.7-4.4L38.8.8 41.3 0l6.2.8 2.6 2.3 3.8 8.7 6.2 13.8 9.6 18.7 2.8 5.5 1.5 5.2.6 1.6h1v-.9l.8-10.6 1.4-12.9L79.2 15.5l.5-4.7 2.3-5.6L86.6 2.2l3.6 1.7 3 4.2-.4 2.8-1.8 11.4-3.4 17.9-2.3 12h1.3l1.5-1.5 6.1-8 10.2-12.8 4.5-5 5.2-5.6 3.4-2.7h6.4l4.7 7-2.1 7.2-6.6 8.3-5.4 7-7.8 10.6-4.9 8.4.5.7 1.1-.1 17.7-3.8 9.5-1.7 11.4-2 5.1 2.4.6 2.5-2 5-12.2 3-14.2 2.8-21.2 5-.3.2.3.4 9.6.9 4 .2h10l18.7 1.4 4.8 3.2 3 4-.5 3-7.5 3.8-10.2-2.4-23.6-5.6-8.1-2H97v.7l6.8 6.6 12.3 11.2 15.5 14.4.8 3.5-2 2.8-2.1-.3-13.6-10.2-5.2-4.6-12-10h-.7v1l2.7 4 14.5 21.8.7 6.7-1 2.1-3.7 1.4-4.2-.8-8.4-11.9-8.8-13.4-7-12-.9.5-4.2 44.8-1.9 2.3-4.5 1.7-3.8-2.8-2-4.7 2-9 2.4-11.9 2-9.5 1.7-11.7 1.1-3.9-.1-.3-.9.1-8.8 12.2-13.5 18.2-10.6 11.4-2.6 1-4.4-2.3.4-4 2.5-3.7 14.7-18.7 8.9-11.6 5.8-6.7v-1h-.4l-39.1 25.4-7 .9-3-2.8.4-4.6 1.4-1.5 11.8-8.1z",
    ],
  },
  codex: {
    label: "Codex",
    viewBox: "0 0 24 24",
    fillRule: "evenodd",
    paths: [
      "M22.28 9.82a5.98 5.98 0 0 0-.51-4.91 6.05 6.05 0 0 0-6.51-2.9A6.07 6.07 0 0 0 4.98 4.18a5.98 5.98 0 0 0-4 2.9 6.05 6.05 0 0 0 .74 7.1 5.98 5.98 0 0 0 .51 4.91 6.05 6.05 0 0 0 6.52 2.9A5.98 5.98 0 0 0 13.26 24a6.06 6.06 0 0 0 5.77-4.21 5.99 5.99 0 0 0 4-2.9 6.06 6.06 0 0 0-.75-7.07zm-9.02 12.6a4.48 4.48 0 0 1-2.88-1.03l.14-.08 4.78-2.76a.79.79 0 0 0 .4-.68v-6.74l2.02 1.17a.07.07 0 0 1 .03.05v5.58a4.5 4.5 0 0 1-4.49 4.5zM3.6 18.3a4.47 4.47 0 0 1-.54-3.02l.15.09 4.78 2.76a.77.77 0 0 0 .78 0l5.84-3.37v2.33a.08.08 0 0 1-.03.06L9.74 19.95a4.5 4.5 0 0 1-6.14-1.65zM2.34 7.9a4.49 4.49 0 0 1 2.37-1.98v5.68a.77.77 0 0 0 .39.68l5.81 3.35-2.02 1.17a.08.08 0 0 1-.07 0l-4.83-2.79A4.5 4.5 0 0 1 2.34 7.9zm16.6 3.86L13.1 8.36l2.02-1.16a.08.08 0 0 1 .07 0l4.83 2.79a4.49 4.49 0 0 1-.68 8.1v-5.67a.79.79 0 0 0-.4-.67zm2.01-3.03l-.14-.08-4.77-2.78a.78.78 0 0 0-.79 0L9.41 9.23V6.9a.07.07 0 0 1 .03-.06l4.83-2.79a4.5 4.5 0 0 1 6.68 4.66zM8.31 12.86l-2.02-1.16a.08.08 0 0 1-.04-.06V6.07a4.5 4.5 0 0 1 7.38-3.45l-.14.08L8.7 5.46a.79.79 0 0 0-.4.68zm1.1-2.36l2.6-1.5 2.6 1.5v3l-2.6 1.5-2.6-1.5z",
    ],
  },
  "acp-cursor": {
    label: "Cursor",
    viewBox: "0 0 24 24",
    paths: [
      "M11.503.131 1.891 5.678a.84.84 0 0 0-.42.726v11.188c0 .3.162.575.42.724l9.609 5.55a1 1 0 0 0 .998 0l9.61-5.55a.84.84 0 0 0 .42-.724V6.404a.84.84 0 0 0-.42-.726L12.497.131a1.01 1.01 0 0 0-.996 0M2.657 6.338h18.55c.263 0 .43.287.297.515L12.23 22.918c-.062.107-.229.064-.229-.06V12.335a.59.59 0 0 0-.295-.51l-9.11-5.257c-.109-.063-.064-.23.061-.23",
    ],
  },
  "acp-grok": {
    label: "Grok Build",
    viewBox: "0.36 0.5 33.33 32",
    paths: [
      "M13.2371 21.0407L24.3186 12.8506C24.8619 12.4491 25.6384 12.6057 25.8973 13.2294C27.2597 16.5185 26.651 20.4712 23.9403 23.1851C21.2297 25.8989 17.4581 26.4941 14.0108 25.1386L10.2449 26.8843C15.6463 30.5806 22.2053 29.6665 26.304 25.5601C29.5551 22.3051 30.562 17.8683 29.6205 13.8673L29.629 13.8758C28.2637 7.99809 29.9647 5.64871 33.449 0.844576C33.5314 0.730667 33.6139 0.616757 33.6964 0.5L29.1113 5.09055V5.07631L13.2343 21.0436",
      "M10.9503 23.0313C7.07343 19.3235 7.74185 13.5853 11.0498 10.2763C13.4959 7.82722 17.5036 6.82767 21.0021 8.2971L24.7595 6.55998C24.0826 6.07017 23.215 5.54334 22.2195 5.17313C17.7198 3.31926 12.3326 4.24192 8.67479 7.90126C5.15635 11.4239 4.0499 16.8403 5.94992 21.4622C7.36924 24.9165 5.04257 27.3598 2.69884 29.826C1.86829 30.7002 1.0349 31.5745 0.36364 32.5L10.9474 23.0341",
    ],
  },
};

/**
 * The agent a thread runs on, drawn by this plugin.
 *
 * Always rendered, so the card's third line has a fixed right edge even when
 * a thread has no branch. `providerId` is a free-form id, so an unknown
 * provider gets a neutral dot rather than nothing.
 */
export function ProviderGlyph({
  providerId,
  className,
}: {
  providerId: string;
  className?: string;
}) {
  const box = cn(TRAILING_GLYPH_BOX_CLASS, className);
  const art = PROVIDER_ART[providerId];

  if (!art) {
    return (
      <span role="img" aria-label={providerId} className={box}>
        <span className="size-2 rounded-full bg-muted-foreground/50" />
      </span>
    );
  }

  return (
    <span className={box}>
      <svg
        viewBox={art.viewBox}
        fill="currentColor"
        fillRule={art.fillRule}
        role="img"
        aria-label={art.label}
        className="size-3 text-muted-foreground/70"
      >
        {art.paths.map((d) => (
          <path key={d} d={d} />
        ))}
      </svg>
    </span>
  );
}
