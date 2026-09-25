import { Icon } from "./components/Icon";
import { cn } from "./lib/utils";
import { useTitleGenerating } from "./title-generation-state";

export function ThreadTitle({
  threadId,
  title,
  className,
}: {
  threadId: string;
  title: string;
  className?: string;
}) {
  const generating = useTitleGenerating(threadId);
  if (!generating) return <span className={className}>{title}</span>;
  return (
    <span
      className={cn(
        "inline-flex min-w-0 max-w-full items-center gap-1.5",
        className,
      )}
    >
      <span className="min-w-0 truncate">{title}</span>
      <span
        role="status"
        aria-label="Generating title"
        className="inline-flex shrink-0 text-muted-foreground/60"
      >
        <Icon
          name="Loading"
          aria-hidden="true"
          className="size-3 animate-spin motion-reduce:animate-none"
        />
      </span>
    </span>
  );
}
