import {
  Select,
  SelectContent,
  SelectItem,
  SelectSeparator,
  SelectTrigger,
} from "./components/Select";
import { Icon } from "./components/Icon";
import { Tooltip } from "./components/Tooltip";
import {
  formatSnoozeWakeTime,
  resolveConfiguredSnoozePreset,
  type ConfiguredSnoozePreset,
} from "./lifecycle";

export function SnoozeSelect({
  label,
  snoozePresets,
  disabled = false,
  triggerClassName,
  onOpenChange,
  onSnooze,
  onPark,
}: {
  label: string;
  snoozePresets: readonly ConfiguredSnoozePreset[];
  disabled?: boolean;
  triggerClassName: string;
  onOpenChange?: (open: boolean) => void;
  onSnooze: (snoozedUntil: number) => void;
  onPark?: () => void;
}) {
  return (
    <Select
      value=""
      disabled={disabled || (snoozePresets.length === 0 && !onPark)}
      onOpenChange={onOpenChange}
      onValueChange={(presetId) => {
        if (presetId === "park") {
          onPark?.();
          return;
        }
        const preset = snoozePresets.find((item) => item.id === presetId);
        if (preset) {
          const wake = resolveConfiguredSnoozePreset(preset);
          if (wake !== null) onSnooze(wake);
        }
      }}
    >
      <Tooltip label={label}>
        <SelectTrigger
          aria-label={label}
          className={`${triggerClassName} [&>svg:last-child]:hidden`}
        >
          <Icon name="Clock" className="size-3.5" />
        </SelectTrigger>
      </Tooltip>
      <SelectContent align="end">
        {snoozePresets.map((preset) => {
          const wake = resolveConfiguredSnoozePreset(preset);
          return (
            <SelectItem
              key={preset.id}
              value={preset.id}
              className="text-xs"
              disabled={wake === null}
              title={wake === null ? "Today's time has passed" : formatSnoozeWakeTime(wake)}
            >
              {preset.label}
            </SelectItem>
          );
        })}
        {onPark ? (
          <>
            {snoozePresets.length > 0 ? <SelectSeparator className="my-1 h-px bg-border" /> : null}
            <SelectItem value="park" className="text-xs">
              <span className="flex items-center gap-2">
                <Icon name="Car" className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
                Park thread
              </span>
            </SelectItem>
          </>
        ) : null}
      </SelectContent>
    </Select>
  );
}
