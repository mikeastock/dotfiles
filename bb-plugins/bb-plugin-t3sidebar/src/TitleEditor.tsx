import { useRef, useState } from "react";
import { cn } from "./lib/utils";

/**
 * A card's title, swapped for an input in place.
 *
 * Backed by `actions.rename`, which the SDK documents as the silent rename
 * meant for exactly this — no dialog, no host UI, the row edits itself.
 *
 * Every exit runs once. Enter commits and unmounts the input, and an unmount
 * can land either side of the blur that follows, so a second commit is a real
 * possibility rather than a defensive one.
 */
export function TitleEditor({
  initialTitle,
  className,
  onCommit,
  onCancel,
}: {
  initialTitle: string;
  className?: string;
  onCommit: (title: string) => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(initialTitle);
  const settled = useRef(false);

  const once = (exit: () => void) => {
    if (settled.current) return;
    settled.current = true;
    exit();
  };

  const commit = () =>
    once(() => {
      const next = value.trim();
      // Blank is not a rename — it is a thread with no name, which bb answers
      // with a generated one. Treat it, and a no-op edit, as a cancel.
      if (next === "" || next === initialTitle.trim()) {
        onCancel();
        return;
      }
      onCommit(next);
    });

  return (
    <input
      autoFocus
      aria-label="Rename thread"
      value={value}
      onChange={(event) => setValue(event.target.value)}
      // The old title is the thing being replaced, so it starts selected —
      // typing overwrites it, and an arrow key still keeps it to edit.
      onFocus={(event) => event.currentTarget.select()}
      onKeyDown={(event) => {
        // bb binds nine sidebar shortcuts to bare keys. Without this, typing a
        // title would also drive the list underneath it.
        event.stopPropagation();
        if (event.key === "Enter") {
          event.preventDefault();
          commit();
        } else if (event.key === "Escape") {
          event.preventDefault();
          once(onCancel);
        }
      }}
      onBlur={commit}
      // The row's full-bleed anchor sits under this input: a click meant for
      // the caret must not also open the thread.
      onClick={(event) => event.stopPropagation()}
      onDoubleClick={(event) => event.stopPropagation()}
      className={cn(
        "pointer-events-auto relative w-full rounded-sm bg-transparent px-0.5 outline-none ring-1 ring-ring",
        className,
      )}
    />
  );
}
