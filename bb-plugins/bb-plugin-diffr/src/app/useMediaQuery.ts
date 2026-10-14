import { useSyncExternalStore } from "react";

/** bb's own compact breakpoint (phones, where the right panel fills the screen). */
export const COMPACT_VIEWPORT_QUERY = "(max-width: 767px)";
export const COARSE_POINTER_QUERY = "(pointer: coarse)";

export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (notify) => {
      const list = window.matchMedia(query);
      list.addEventListener("change", notify);
      return () => list.removeEventListener("change", notify);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}
