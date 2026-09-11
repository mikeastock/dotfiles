export const DEFAULT_INACTIVE_AFTER_HOURS = 6;
export const MIN_INACTIVE_AFTER_HOURS = 1;
export const MAX_INACTIVE_AFTER_HOURS = 720;

const HOUR_MS = 60 * 60 * 1_000;

export interface InactiveThread {
  createdAt: number;
  latestAttentionAt: number;
  updatedAt: number;
}

/** Invalid settings keep threads in Active instead of hiding them. */
export function parseInactiveAfterHours(
  enabled: boolean,
  rawHours: string,
): number | null {
  if (!enabled) return null;
  const hours = Number(rawHours);
  return Number.isInteger(hours) &&
    hours >= MIN_INACTIVE_AFTER_HOURS &&
    hours <= MAX_INACTIVE_AFTER_HOURS
    ? hours
    : null;
}

export function isInactiveThread(
  thread: InactiveThread,
  now: number,
  afterHours: number | null,
): boolean {
  if (afterHours === null) return false;
  const lastActivityAt = Math.max(
    thread.createdAt,
    thread.updatedAt,
    thread.latestAttentionAt,
  );
  return lastActivityAt <= now - afterHours * HOUR_MS;
}
