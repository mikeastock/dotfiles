import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import { SnoozeSelect } from "./SnoozeSelect";
import type { ConfiguredSnoozePreset } from "./lifecycle";

export function BulkSelectionBar({
  count,
  busy,
  snoozePresets,
  onSettle,
  onSnooze,
  onMarkRead,
  onMarkUnread,
  onClear,
}: {
  count: number;
  busy: boolean;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  onSettle: () => void;
  onSnooze: (snoozedUntil: number) => void;
  onMarkRead: () => void;
  onMarkUnread: () => void;
  onClear: () => void;
}) {
  return (
    <div
      role="toolbar"
      aria-label={`${count} threads selected`}
      className="flex h-7 min-w-0 flex-1 items-center gap-0.5"
    >
      <span className="min-w-0 flex-1 truncate px-1 text-xs font-medium text-foreground">
        {count} selected
      </span>
      <ActionButton
        label="Settle selected threads"
        icon="Check"
        disabled={busy}
        onClick={onSettle}
      />
      <SnoozeSelect
        label="Snooze selected threads"
        snoozePresets={snoozePresets}
        disabled={busy || snoozePresets.length === 0}
        triggerClassName="h-7 w-9 border-0 px-1.5 py-1 shadow-none hover:bg-sidebar-accent focus:ring-0 [&>svg:last-child]:size-3"
        onSnooze={onSnooze}
      />
      <ActionButton
        label="Mark selected threads read"
        icon="MailOpen"
        disabled={busy}
        onClick={onMarkRead}
      />
      <ActionButton
        label="Mark selected threads unread"
        icon="Mail"
        disabled={busy}
        onClick={onMarkUnread}
      />
      <ActionButton
        label="Clear selection"
        icon="CircleX"
        disabled={busy}
        onClick={onClear}
      />
    </div>
  );
}

function ActionButton({
  label,
  icon,
  disabled,
  onClick,
}: {
  label: string;
  icon: "Check" | "Mail" | "MailOpen" | "CircleX";
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <Tooltip label={label}>
      <button
        type="button"
        aria-label={label}
        disabled={disabled}
        onClick={onClick}
        className="flex size-7 shrink-0 items-center justify-center rounded text-muted-foreground hover:bg-sidebar-accent hover:text-foreground disabled:cursor-not-allowed disabled:opacity-50"
      >
        <Icon name={icon} className="size-3.5" />
      </button>
    </Tooltip>
  );
}
