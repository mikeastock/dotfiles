import { useId, useRef, useState } from "react";
import { BotAvatar } from "./BotAvatar";
import {
  BOT_AVATAR_COLORS,
  BOT_AVATAR_EXPRESSIONS,
  BOT_AVATAR_SHAPES,
  randomAvatar,
  type BotAvatar as BotAvatarData,
  type BotDraft,
  type BotHost,
  type EditorBot,
} from "./bots";
import {
  Dialog,
  fieldInputClass,
  ghostButtonClass,
  primaryButtonClass,
} from "./components/Dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./components/Select";
import { cn } from "./lib/utils";

export type BotEditorTarget =
  | { kind: "create" }
  | { kind: "edit"; bot: EditorBot };

const SOUL_MAX = 4096;

/**
 * Create or edit a bot, compactly: name and role beside the face, the
 * machine it runs on, the face's colour, silhouette and expression, and its
 * instructions. Save is explicit; Enter in a text field never submits.
 *
 * The bots plugin owns the bot. This form only fills in the fields its
 * `bot_create` / `bot_update` RPCs take, and hands them over.
 */
export function BotEditorDialog({
  target,
  hosts,
  onClose,
  onSave,
}: {
  target: BotEditorTarget;
  hosts: readonly BotHost[];
  onClose: () => void;
  onSave: (draft: BotDraft) => Promise<void>;
}) {
  const editing = target.kind === "edit";
  const [name, setName] = useState(editing ? target.bot.name : "");
  const [role, setRole] = useState(editing ? target.bot.role : "");
  const [hostId, setHostId] = useState(
    editing && target.bot.hostId
      ? target.bot.hostId
      : (hosts.find((host) => host.connected)?.id ?? hosts[0]?.id ?? ""),
  );
  // Rolled once per open, never on a re-render: a draft must hold still.
  const [avatar, setAvatar] = useState<BotAvatarData>(() =>
    editing ? target.bot.avatar : randomAvatar(),
  );
  const [soul, setSoul] = useState(editing ? target.bot.soul : "");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const saving = useRef(false);
  const ids = {
    name: useId(),
    role: useId(),
    host: useId(),
    soul: useId(),
  };

  const canSave =
    name.trim().length > 0 && hostId.length > 0 && !pending && soul.length <= SOUL_MAX;

  const save = async () => {
    if (!canSave || saving.current) return;
    saving.current = true;
    setPending(true);
    setError(null);
    try {
      await onSave({ name: name.trim(), role: role.trim(), hostId, avatar, soul });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      saving.current = false;
      setPending(false);
    }
  };

  return (
    <Dialog
      title={editing ? `Edit ${target.bot.name}` : "New bot"}
      description={
        editing
          ? "Identity and instructions live in the Bots Sidebar plugin; this saves them there."
          : "A bot is an identity with its own instructions and memory. Conversations you start with it, or assign to it, group under it."
      }
      onClose={() => {
        if (!saving.current) onClose();
      }}
      footer={
        <>
          <button
            type="button"
            className={ghostButtonClass}
            disabled={pending}
            onClick={onClose}
          >
            Cancel
          </button>
          <button
            type="button"
            className={primaryButtonClass}
            disabled={!canSave}
            onClick={() => void save()}
          >
            {pending ? "Saving…" : editing ? "Save bot" : "Create bot"}
          </button>
        </>
      }
    >
      <div className="flex items-start gap-3">
        <span className="flex size-12 shrink-0 items-center justify-center">
          <BotAvatar avatar={avatar} size={44} />
        </span>
        <div className="grid min-w-0 flex-1 grid-cols-1 gap-2 sm:grid-cols-2">
          <Field label="Name" htmlFor={ids.name}>
            <input
              id={ids.name}
              autoFocus
              value={name}
              maxLength={120}
              onChange={(event) => setName(event.target.value)}
              onKeyDown={swallowEnter}
              placeholder="Reviewer"
              className={fieldInputClass}
            />
          </Field>
          <Field label="Role" htmlFor={ids.role}>
            <input
              id={ids.role}
              value={role}
              maxLength={80}
              onChange={(event) => setRole(event.target.value)}
              onKeyDown={swallowEnter}
              placeholder="Code review"
              className={fieldInputClass}
            />
          </Field>
          <Field label="Machine" htmlFor={ids.host}>
            <Select value={hostId} onValueChange={setHostId}>
              <SelectTrigger
                id={ids.host}
                aria-label="Machine"
                className="h-8 text-sm"
              >
                <SelectValue placeholder="Choose a machine" />
              </SelectTrigger>
              <SelectContent>
                {hostId && !hosts.some((host) => host.id === hostId) ? (
                  <SelectItem value={hostId} disabled>
                    Unavailable machine
                  </SelectItem>
                ) : null}
                {hosts.map((host) => (
                  <SelectItem key={host.id} value={host.id}>
                    {host.name}
                    {host.connected ? "" : " (offline)"}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </div>
      </div>

      <fieldset className="space-y-2">
        <div className="flex items-center justify-between">
          <legend className="text-xs font-medium text-muted-foreground">
            Appearance
          </legend>
          <button
            type="button"
            className="h-7 rounded-md px-2 text-xs text-muted-foreground hover:bg-sidebar-accent hover:text-foreground"
            onClick={() => setAvatar(randomAvatar())}
          >
            Randomize
          </button>
        </div>
        <div
          role="group"
          aria-label="Color"
          className="flex flex-wrap items-center gap-1.5"
        >
          {BOT_AVATAR_COLORS.map((color) => (
            <button
              key={color}
              type="button"
              aria-label={`Color ${color}`}
              aria-pressed={avatar.color === color}
              onClick={() => setAvatar({ ...avatar, color })}
              className="size-5 rounded-full border-2 border-background ring-offset-1 ring-offset-background aria-pressed:ring-2 aria-pressed:ring-foreground"
              style={{ background: color }}
            />
          ))}
          <input
            type="color"
            aria-label="Custom color"
            value={avatar.color}
            onChange={(event) =>
              setAvatar({ ...avatar, color: event.target.value })
            }
            className="size-5 cursor-pointer rounded border-0 bg-transparent p-0"
          />
        </div>
        <div role="group" aria-label="Shape" className="flex flex-wrap gap-1">
          {BOT_AVATAR_SHAPES.map((shape) => (
            <button
              key={shape}
              type="button"
              aria-label={`Shape ${shape}`}
              aria-pressed={avatar.shape === shape}
              onClick={() => setAvatar({ ...avatar, shape })}
              className={cn(
                "flex size-8 items-center justify-center rounded-md hover:bg-sidebar-accent",
                avatar.shape === shape && "bg-sidebar-accent ring-1 ring-ring",
              )}
            >
              <BotAvatar avatar={{ ...avatar, shape }} size={22} />
            </button>
          ))}
        </div>
        <div
          role="group"
          aria-label="Expression"
          className="flex flex-wrap gap-1"
        >
          {BOT_AVATAR_EXPRESSIONS.map((expression) => (
            <button
              key={expression}
              type="button"
              aria-label={`Expression ${expression}`}
              aria-pressed={avatar.expression === expression}
              onClick={() => setAvatar({ ...avatar, expression })}
              className={cn(
                "flex size-8 items-center justify-center rounded-md hover:bg-sidebar-accent",
                avatar.expression === expression &&
                  "bg-sidebar-accent ring-1 ring-ring",
              )}
            >
              <BotAvatar avatar={{ ...avatar, expression }} size={22} />
            </button>
          ))}
        </div>
      </fieldset>

      <Field
        label="Instructions"
        htmlFor={ids.soul}
        hint={`${soul.length} / ${SOUL_MAX}`}
      >
        <textarea
          id={ids.soul}
          value={soul}
          rows={6}
          maxLength={SOUL_MAX}
          onChange={(event) => setSoul(event.target.value)}
          placeholder="Who this bot is and how it works. Memory and settings are kept by the bot itself."
          className={cn(
            fieldInputClass,
            "h-auto resize-y py-2 font-mono text-xs leading-5",
          )}
        />
      </Field>

      {error ? (
        <p role="alert" className="text-xs text-destructive-text">
          {error}
        </p>
      ) : null}
    </Dialog>
  );
}

function Field({
  label,
  htmlFor,
  hint,
  children,
}: {
  label: string;
  htmlFor: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="min-w-0 space-y-1">
      <div className="flex items-baseline justify-between">
        <label
          htmlFor={htmlFor}
          className="text-xs font-medium text-muted-foreground"
        >
          {label}
        </label>
        {hint ? (
          <span className="text-2xs tabular-nums text-muted-foreground/70">
            {hint}
          </span>
        ) : null}
      </div>
      {children}
    </div>
  );
}

/** Enter in a text field must not submit: Save is explicit. */
function swallowEnter(event: React.KeyboardEvent<HTMLInputElement>) {
  if (event.key === "Enter") event.preventDefault();
}
