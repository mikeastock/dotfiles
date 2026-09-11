import { useRef, useState } from "react";
import {
  experimental_NewThreadComposer as NewThreadComposer,
  type NewThreadRequest,
} from "@get-bb/plugin-sdk/app";
import type { SidebarBot } from "./bots";
import { Dialog } from "./components/Dialog";

/**
 * A new conversation with a bot, in bb's own composer.
 *
 * The composer is the host's: prompt, attachments, provider, model,
 * environment and project picker all behave as on the compose screen. The
 * one difference is where the request goes on send — to the bots plugin's
 * `conversation_create`, which spawns the thread and binds it to the bot,
 * so it lands under the bot's row rather than in the plain list.
 *
 * Seeded projectless on the bot's machine, the way the bots plugin starts an
 * ordinary chat; the picker stays editable.
 */
export function BotConversationDialog({
  bot,
  personalProjectId,
  makeMain,
  onClose,
  onCreate,
}: {
  bot: SidebarBot;
  personalProjectId: string | null;
  /** True for a bot's first conversation, which becomes its main one. */
  makeMain: boolean;
  onClose: () => void;
  onCreate: (request: NewThreadRequest) => Promise<void>;
}) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submitting = useRef(false);

  return (
    <Dialog
      title={makeMain ? `Start ${bot.name}` : `New conversation with ${bot.name}`}
      description={
        makeMain
          ? "This first conversation becomes the bot's main one. Choose the project, machine and model before sending."
          : "Choose the project, machine and model before sending. The conversation groups under the bot."
      }
      className="sm:max-w-3xl"
      onClose={() => {
        if (!submitting.current) onClose();
      }}
    >
      <NewThreadComposer
        {...(personalProjectId ? { defaultProjectId: personalProjectId } : {})}
        {...(bot.hostId
          ? {
              defaultEnvironment: {
                type: "host",
                hostId: bot.hostId,
                workspace: { type: "personal" },
              },
            }
          : {})}
        layout="document"
        focusRequest={1}
        draftKey={`bb-sidebar:bot:${bot.id}:${makeMain ? "main" : "chat"}`}
        onSubmit={async (request) => {
          if (submitting.current) {
            throw new Error("A conversation is already being created.");
          }
          submitting.current = true;
          setPending(true);
          setError(null);
          try {
            await onCreate(request);
          } catch (cause) {
            setError(cause instanceof Error ? cause.message : String(cause));
            throw cause;
          } finally {
            submitting.current = false;
            setPending(false);
          }
        }}
      />
      {error ? (
        <p role="alert" className="text-xs text-destructive-text">
          {error}
        </p>
      ) : null}
      {pending ? (
        <p role="status" className="text-xs text-muted-foreground">
          Creating conversation…
        </p>
      ) : null}
    </Dialog>
  );
}
