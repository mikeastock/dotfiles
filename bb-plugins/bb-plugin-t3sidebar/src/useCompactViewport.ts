import { createContext, useContext, type CSSProperties } from "react";

/**
 * Whether the host is drawing this sidebar on a phone-width viewport or a
 * coarse pointer — bb's `isCompactViewport`, shared with every row.
 *
 * The host hands that flag to the list component alone, and the rows that have
 * to answer for it sit three levels below. One context beats threading a
 * boolean through the list, each shelf, each card and each status slot.
 *
 * A coarse pointer flips this even on a wide screen, so read it as "no hover,
 * fat finger" rather than "narrow". Defaults to false, which is what a
 * component rendered outside the list should get.
 */
const CompactViewportContext = createContext(false);

export const CompactViewportProvider = CompactViewportContext.Provider;

export function useIsCompactViewport(): boolean {
  return useContext(CompactViewportContext);
}

/**
 * Grows a control's hit area to roughly 44px without changing what it draws.
 *
 * A coarse pointer needs a target the row has no room to render: the card's
 * top line is 20px tall and the icons in it are 14px. A pseudo-element takes
 * the press outside the control's own box, so the layout — and the desktop
 * density this sidebar is built around — stays exactly as it was.
 */
export const TOUCH_TARGET_CLASS =
  "before:absolute before:left-1/2 before:top-1/2 before:size-11 before:-translate-x-1/2 before:-translate-y-1/2 before:content-['']";

/**
 * Stops iOS raising its own link callout over a row's full-bleed anchor.
 *
 * Radix's context-menu trigger sets exactly this, and used to cover the rows
 * for free. That trigger is not mounted on a compact viewport any more, so a
 * row holding a link has to say it itself or a press lands on the system
 * sheet instead of the row.
 */
export const NO_TOUCH_CALLOUT: CSSProperties = { WebkitTouchCallout: "none" };
