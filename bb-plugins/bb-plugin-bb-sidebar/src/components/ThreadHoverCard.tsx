import { useCallback, useEffect, useId, useRef, type ReactElement, type ReactNode } from "react";
import * as Popover from "@radix-ui/react-popover";
import { usePortalScopeProps } from "../lib/portal-scope";

const HOVER_CARD_OPENED = "bb-sidebar:thread-hover-card-opened";

/** Hover preview with a keyboard path into its links. Blank areas pass clicks through. */
export function ThreadHoverCard({ children, content, open, onOpenChange }: {
  children: ReactElement;
  content: ReactNode;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const anchor = useRef<HTMLElement | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const restoreFocus = useRef(false);
  const pointerDown = useRef(false);
  const releasePointer = useCallback(() => { pointerDown.current = false; }, []);
  const panelId = useId();
  const clearTimer = () => {
    clearTimeout(timer.current);
    timer.current = undefined;
  };
  const scheduleClose = () => {
    clearTimer();
    timer.current = setTimeout(() => {
      timer.current = undefined;
      if (!panel.current?.contains(document.activeElement)) onOpenChange(false);
    }, 300);
  };
  useEffect(() => () => {
    clearTimeout(timer.current);
    document.removeEventListener("pointerup", releasePointer);
    document.removeEventListener("pointercancel", releasePointer);
  }, [releasePointer]);
  useEffect(() => {
    if (!open) return;
    // A focused disclosure can keep its card open after pointer leave. A new
    // preview takes precedence, including over a card entered with Tab.
    document.dispatchEvent(new Event(HOVER_CARD_OPENED));
    const closeForAnotherCard = () => {
      clearTimer();
      restoreFocus.current = false;
      onOpenChange(false);
    };
    document.addEventListener(HOVER_CARD_OPENED, closeForAnotherCard);
    return () => document.removeEventListener(HOVER_CARD_OPENED, closeForAnotherCard);
  }, [open, onOpenChange]);
  useEffect(() => {
    if (!open) return;
    const trackPointer = (event: PointerEvent) => {
      if (event.pointerType === "touch") return;
      const inside = [panel.current, anchor.current].some((element) => {
        const rect = element?.getBoundingClientRect();
        return rect && event.clientX >= rect.left && event.clientX <= rect.right && event.clientY >= rect.top && event.clientY <= rect.bottom;
      });
      if (inside) clearTimer();
      else if (timer.current === undefined) scheduleClose();
    };
    document.addEventListener("pointermove", trackPointer, { passive: true });
    return () => document.removeEventListener("pointermove", trackPointer);
  }, [open, onOpenChange]);

  return (
    <Popover.Root open={open} onOpenChange={onOpenChange} modal={false}>
      <Popover.Anchor asChild
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        aria-describedby={open ? `${panelId}-description` : undefined}
        onPointerDown={() => {
          clearTimer();
          pointerDown.current = true;
          onOpenChange(false);
          document.addEventListener("pointerup", releasePointer, { once: true });
          document.addEventListener("pointercancel", releasePointer, { once: true });
        }}
        onClick={() => { clearTimer(); onOpenChange(false); }}
        onPointerMove={(event) => {
          anchor.current = event.currentTarget;
          if (event.pointerType === "touch" || pointerDown.current) return;
          clearTimer();
          if (open) return;
          timer.current = setTimeout(() => onOpenChange(true), 250);
        }}
        onPointerLeave={scheduleClose}
        onFocus={(event) => {
          anchor.current = event.currentTarget;
          clearTimer();
          if (restoreFocus.current || pointerDown.current) return;
          onOpenChange(true);
        }}
        onKeyDown={(event) => {
          if (event.key === "Tab" && !event.shiftKey && open) {
            const first = panel.current?.querySelector<HTMLElement>("a[href], button:not([disabled]), [data-port-scroll]");
            if (first) {
              event.preventDefault();
              restoreFocus.current = true;
              first.focus();
            }
          }
          if (event.key === "Escape") onOpenChange(false);
        }}
      >{children}</Popover.Anchor>
      <Popover.Portal>
        <Popover.Content
          {...usePortalScopeProps()}
          ref={panel}
          id={panelId}
          side="right"
          sideOffset={6}
          aria-label="Thread details"
          onOpenAutoFocus={(event) => event.preventDefault()}
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            if (restoreFocus.current) anchor.current?.focus();
            restoreFocus.current = false;
          }}
          onEscapeKeyDown={() => { restoreFocus.current = true; }}
          onPointerEnter={clearTimer}
          onPointerLeave={scheduleClose}
          onFocusCapture={clearTimer}
          onKeyDown={(event) => {
            const first = panel.current?.querySelector("a[href], button:not([disabled]), [data-port-scroll]");
            if (event.key === "Tab" && event.shiftKey && event.target === first) {
              event.preventDefault();
              restoreFocus.current = true;
              onOpenChange(false);
            }
          }}
          onInteractOutside={(event) => {
            if (anchor.current?.contains(event.detail.originalEvent.target as Node)) event.preventDefault();
            else restoreFocus.current = false;
          }}
          className="pointer-events-none z-50 max-h-[calc(100dvh-24px)] w-64 max-w-[calc(100vw-24px)] overflow-y-auto rounded-lg border border-border bg-popover p-2.5 text-xs text-popover-foreground shadow-xl outline-none"
        ><div id={`${panelId}-description`}>{content}</div></Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
