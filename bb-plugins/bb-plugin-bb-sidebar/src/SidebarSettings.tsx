import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import {
  cachedSidebarSettings,
  cacheSidebarSettings,
  DEFAULT_SIDEBAR_SETTINGS,
  SIDEBAR_SETTINGS_CHANNEL,
  type SidebarSettingsValues,
} from "./sidebar-settings";
import { ProjectIconSettings } from "./ProjectIconSettings";
import { ProjectRemovalSettings } from "./ProjectRemovalSettings";

function SettingsGroup({
  children,
  description,
  title,
}: {
  children: ReactNode;
  description: string;
  title: string;
}) {
  return (
    <section aria-labelledby={`settings-${title.toLowerCase().replaceAll(" ", "-")}`}>
      <div className="mb-3">
        <h2
          id={`settings-${title.toLowerCase().replaceAll(" ", "-")}`}
          className="text-sm font-semibold text-foreground"
        >
          {title}
        </h2>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">
          {description}
        </p>
      </div>
      <div className="overflow-hidden rounded-lg border border-border bg-card">
        {children}
      </div>
    </section>
  );
}

function SettingRow({
  children,
  description,
  title,
}: {
  children: ReactNode;
  description: string;
  title: string;
}) {
  return (
    <div className="flex min-h-16 items-center justify-between gap-6 border-b border-border px-4 py-3 last:border-b-0">
      <div className="min-w-0">
        <p className="text-sm font-medium text-foreground">{title}</p>
        <p className="mt-0.5 text-xs leading-5 text-muted-foreground">
          {description}
        </p>
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function Switch({
  checked,
  disabled,
  label,
  onChange,
}: {
  checked: boolean;
  disabled?: boolean;
  label: string;
  onChange: (checked: boolean) => void;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative h-6 w-11 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${
        checked ? "bg-primary" : "bg-muted"
      }`}
    >
      <span
        className={`absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-background shadow-sm transition-transform ${
          checked ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  );
}

const numberInputClass =
  "h-9 w-24 rounded-md border border-border bg-background px-2.5 text-right text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring disabled:cursor-not-allowed disabled:bg-muted disabled:text-muted-foreground";

export function SidebarSettings() {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const loadRequestSeq = useRef(0);
  const initialSettings = cachedSidebarSettings(rpc);
  const [saved, setSaved] = useState<SidebarSettingsValues>(
    initialSettings ?? DEFAULT_SIDEBAR_SETTINGS,
  );
  const [draft, setDraft] = useState<SidebarSettingsValues>(
    initialSettings ?? DEFAULT_SIDEBAR_SETTINGS,
  );
  const savedRef = useRef(saved);
  const draftRef = useRef(draft);
  savedRef.current = saved;
  draftRef.current = draft;
  const [loading, setLoading] = useState(initialSettings === null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    const seq = ++loadRequestSeq.current;
    try {
      const result = await rpc.call("getSidebarSettings", {});
      if (seq !== loadRequestSeq.current) return;
      const cached = cacheSidebarSettings(rpc, result);
      const hasLocalEdits =
        JSON.stringify(draftRef.current) !== JSON.stringify(savedRef.current);
      savedRef.current = cached;
      setSaved(cached);
      if (!hasLocalEdits) {
        draftRef.current = cached;
        setDraft(cached);
      }
    } catch (error) {
      if (seq !== loadRequestSeq.current) return;
      toast.error("Could not load sidebar settings", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      if (seq === loadRequestSeq.current) setLoading(false);
    }
  }, [rpc]);

  useEffect(() => {
    void load();
  }, [load]);
  useRealtime(SIDEBAR_SETTINGS_CHANNEL, () => {
    void load();
  });

  const dirty = JSON.stringify(draft) !== JSON.stringify(saved);
  const update = <Key extends keyof SidebarSettingsValues>(
    key: Key,
    value: SidebarSettingsValues[Key],
  ) =>
    setDraft((current) => {
      const next = { ...current, [key]: value };
      draftRef.current = next;
      return next;
    });

  const save = async () => {
    if (!dirty || saving) return;
    // A load started before this write cannot overwrite its result.
    loadRequestSeq.current += 1;
    setSaving(true);
    try {
      const result = await rpc.call("updateSidebarSettings", draft);
      const cached = cacheSidebarSettings(rpc, result);
      savedRef.current = cached;
      draftRef.current = cached;
      setSaved(cached);
      setDraft(cached);
      toast.success("Sidebar settings saved");
    } catch (error) {
      toast.error("Could not save sidebar settings", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="max-w-3xl rounded-lg border border-border px-4 py-8 text-center text-sm text-muted-foreground">
        Loading settings...
      </div>
    );
  }

  return (
    <div className="max-w-3xl space-y-8 pb-4">
      <SettingsGroup
        title="Thread organization"
        description="Choose when threads leave Active and which snooze shortcuts appear in the sidebar."
      >
        <SettingRow
          title="Inactive shelf"
          description="Move quiet, unpinned threads out of Active. New activity moves them back."
        >
          <Switch
            label="Inactive shelf"
            checked={draft.inactiveThreadsEnabled}
            onChange={(checked) => update("inactiveThreadsEnabled", checked)}
          />
        </SettingRow>
        <SettingRow
          title="Move after"
          description="Hours without thread activity."
        >
          <div className="flex items-center gap-2">
            <input
              type="number"
              aria-label="Hours before inactive"
              min={1}
              max={720}
              value={draft.inactiveAfterHours}
              disabled={!draft.inactiveThreadsEnabled}
              onChange={(event) =>
                update("inactiveAfterHours", Number(event.target.value))
              }
              className={numberInputClass}
            />
            <span className="w-10 text-xs text-muted-foreground">hours</span>
          </div>
        </SettingRow>
        <SettingRow
          title="Snooze shortcuts"
          description="Comma-separated durations shown in the snooze menu. Add a label with Lunch=3h."
        >
          <input
            aria-label="Snooze shortcuts"
            value={draft.snoozePresets}
            onChange={(event) => update("snoozePresets", event.target.value)}
            className="h-9 w-56 rounded-md border border-border bg-background px-2.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring"
          />
        </SettingRow>
      </SettingsGroup>

      <SettingsGroup
        title="Automatic cleanup"
        description="Settle finished work automatically. Settled threads remain available in their own shelf."
      >
        <SettingRow
          title="Settle inactive threads"
          description="Move threads to Settled after a longer quiet period."
        >
          <Switch
            label="Settle inactive threads"
            checked={draft.autoSettleInactive}
            onChange={(checked) => update("autoSettleInactive", checked)}
          />
        </SettingRow>
        <SettingRow
          title="Settle after"
          description="Days without thread activity."
        >
          <div className="flex items-center gap-2">
            <input
              type="number"
              aria-label="Days before auto-settle"
              min={1}
              max={90}
              value={draft.autoSettleAfterDays}
              disabled={!draft.autoSettleInactive}
              onChange={(event) =>
                update("autoSettleAfterDays", Number(event.target.value))
              }
              className={numberInputClass}
            />
            <span className="w-10 text-xs text-muted-foreground">days</span>
          </div>
        </SettingRow>
        <SettingRow
          title="Settle merged pull requests"
          description="Settle a thread when its pull request is merged."
        >
          <Switch
            label="Settle merged pull requests"
            checked={draft.autoSettleOnMerge}
            onChange={(checked) => update("autoSettleOnMerge", checked)}
          />
        </SettingRow>
      </SettingsGroup>

      <div className="flex items-center justify-end gap-3">
        {dirty ? (
          <span className="text-xs text-muted-foreground">Unsaved changes</span>
        ) : null}
        <button
          type="button"
          disabled={!dirty || saving}
          onClick={() => void save()}
          className="h-9 rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {saving ? "Saving..." : "Save changes"}
        </button>
      </div>

      <ProjectIconSettings />
      <ProjectRemovalSettings />
    </div>
  );
}
