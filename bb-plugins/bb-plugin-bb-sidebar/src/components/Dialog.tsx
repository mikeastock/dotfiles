import type { ReactNode } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import { cn } from "../lib/utils";
import { usePortalScopeProps } from "../lib/portal-scope";

/**
 * A modal for this plugin's own forms, on bb's shimmed Radix dialog.
 *
 * Portaled content leaves the plugin's mount, so the content carries the
 * portal-scope attributes that bring the plugin's styles back with it.
 */
export function Dialog({
  title,
  description,
  onClose,
  children,
  footer,
  className,
}: {
  title: string;
  description?: string;
  /** Called when the user dismisses; ignored while `closeLocked` is true. */
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  className?: string;
}) {
  const portalScope = usePortalScopeProps();
  return (
    <DialogPrimitive.Root
      open
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
    >
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay
          {...portalScope}
          className="fixed inset-0 z-50 bg-black/40"
        />
        <DialogPrimitive.Content
          {...portalScope}
          onOpenAutoFocus={(event) => event.preventDefault()}
          className={cn(
            "fixed left-1/2 top-1/2 z-50 flex max-h-[90vh] w-[min(92vw,42rem)] -translate-x-1/2 -translate-y-1/2 flex-col gap-4 overflow-y-auto rounded-lg border border-border bg-background p-5 text-foreground shadow-lg",
            className,
          )}
        >
          <div className="space-y-1">
            <DialogPrimitive.Title className="text-base font-semibold">
              {title}
            </DialogPrimitive.Title>
            {description ? (
              <DialogPrimitive.Description className="text-xs leading-5 text-muted-foreground">
                {description}
              </DialogPrimitive.Description>
            ) : (
              <DialogPrimitive.Description className="sr-only">
                {title}
              </DialogPrimitive.Description>
            )}
          </div>
          {children}
          {footer ? (
            <div className="flex items-center justify-end gap-2">{footer}</div>
          ) : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export const dialogButtonClass =
  "h-8 rounded-md px-3 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50";
export const primaryButtonClass = cn(
  dialogButtonClass,
  "bg-primary text-primary-foreground hover:bg-primary/90",
);
export const ghostButtonClass = cn(
  dialogButtonClass,
  "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
);
export const fieldInputClass =
  "h-8 w-full rounded-md border border-border bg-background px-2.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring";
