import { useRef, type ReactNode } from "react";
import * as ContextMenu from "@radix-ui/react-context-menu";
import { useRpc } from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { Icon, type IconName } from "./components/Icon";
import { cn } from "./lib/utils";
import { usePortalScopeProps } from "./lib/portal-scope";
import { TRAILING_GLYPH_BOX_CLASS } from "./StatusSlot";
import {
  channelHref,
  channelIdFromPath,
  type ChannelStateInput,
  type SidebarChannel,
} from "./channels";
import { usePathname } from "./useChannels";

/**
 * Bot Teams channels as slim rows. Each row is a plain link to the channel's
 * Bot Teams page; bb routes it in place, and Bot Teams marks the channel read
 * when it opens. The context menu covers the everyday state changes; rename,
 * delete, members, and search stay on Bot Teams' own Channels page.
 */
export function ChannelsShelf({
  channels,
  expanded,
  onNavigate,
  onChanged,
}: {
  channels: readonly SidebarChannel[];
  /**
   * Collapsed, like the other shelves, still shows the row on screen — plus
   * any channel waiting on the user, which should never be folded away.
   */
  expanded: boolean;
  onNavigate: () => void;
  /** Re-read channels after a write, so the row updates at once. */
  onChanged: () => void;
}) {
  const currentChannelId = channelIdFromPath(usePathname());
  const rpc = useRpc<typeof bbSidebarRpcContract>();

  const setState = async (input: ChannelStateInput, failure: string) => {
    try {
      await rpc.call("setChannelState", input);
      onChanged();
    } catch (error) {
      toast.error(failure, {
        description: error instanceof Error ? error.message : undefined,
      });
    }
  };

  const visible = expanded
    ? channels
    : channels.filter(
        (channel) =>
          channel.id === currentChannelId || channel.needsYouCount > 0,
      );
  if (visible.length === 0) return null;

  return (
    <ul className="flex flex-col gap-px">
      {visible.map((channel) => (
        <ChannelRow
          key={channel.id}
          channel={channel}
          isActive={channel.id === currentChannelId}
          onOpen={() => {
            onNavigate();
            if (channel.unread) {
              void setState(
                { id: channel.id, lastReadAt: channel.updatedAt },
                "Could not mark channel read",
              );
            }
          }}
          onSetState={(patch, failure) =>
            void setState({ id: channel.id, ...patch }, failure)
          }
        />
      ))}
    </ul>
  );
}

function ChannelRow({
  channel,
  isActive,
  onOpen,
  onSetState,
}: {
  channel: SidebarChannel;
  isActive: boolean;
  onOpen: () => void;
  onSetState: (patch: Omit<ChannelStateInput, "id">, failure: string) => void;
}) {
  const link = useRef<HTMLAnchorElement>(null);
  const portalScope = usePortalScopeProps();
  const unread = channel.unread && !isActive;
  const needsYouLabel =
    channel.needsYouCount === 1
      ? "1 request needs you"
      : `${channel.needsYouCount} requests need you`;
  const statusLabel = [
    channel.needsYouCount > 0 && needsYouLabel,
    channel.working && "Working",
    unread && "Unread",
  ]
    .filter(Boolean)
    .join(", ");

  return (
    <ContextMenu.Root>
      <ContextMenu.Trigger asChild>
        <li className="list-none">
          <div
            className={cn(
              "group/channel relative flex h-8 items-center gap-2 rounded-md px-2.5 text-xs transition-colors duration-150 ease-out motion-reduce:transition-none",
              isActive ? "bg-sidebar-accent" : "hover:bg-sidebar-accent/60",
            )}
          >
            <a
              ref={link}
              href={channelHref(channel.id)}
              aria-label={
                statusLabel ? `${channel.name} (${statusLabel})` : channel.name
              }
              aria-current={isActive ? "page" : undefined}
              onClick={(event) => {
                // Modified clicks are bb's: its link handler opens a split.
                if (event.metaKey || event.ctrlKey) return;
                onOpen();
              }}
              className="absolute inset-0 cursor-pointer rounded-md"
            />
            <span
              className={cn(
                "pointer-events-none relative flex min-w-0 flex-1 items-center gap-1.5",
                isActive || unread
                  ? "text-foreground"
                  : "text-foreground/80 group-hover/channel:text-foreground",
                unread && "font-medium",
              )}
            >
              {channel.needsYouCount > 0 ? (
                <Icon
                  name="BubbleChatNotification"
                  className="size-3.5 shrink-0 text-amber-500"
                  aria-hidden
                />
              ) : channel.pinned ? (
                <Icon
                  name="Pin"
                  className="size-3.5 shrink-0 text-muted-foreground/70"
                  aria-hidden
                />
              ) : (
                <span
                  aria-hidden
                  className="w-3.5 shrink-0 text-center text-muted-foreground/70"
                >
                  #
                </span>
              )}
              <span className="min-w-0 flex-1 truncate">{channel.name}</span>
            </span>
            <span className="pointer-events-none relative flex shrink-0 items-center gap-1.5">
              {channel.needsYouCount > 1 ? (
                <span className="tabular-nums text-2xs text-amber-500">
                  {channel.needsYouCount}
                </span>
              ) : null}
              <span className={TRAILING_GLYPH_BOX_CLASS}>
                {channel.working ? (
                  <Icon
                    name="Loading"
                    className="size-3.5 animate-spin text-muted-foreground motion-reduce:animate-none"
                    aria-hidden
                  />
                ) : unread ? (
                  <span
                    aria-hidden
                    className="size-1.5 rounded-full bg-foreground/80"
                  />
                ) : null}
              </span>
            </span>
          </div>
        </li>
      </ContextMenu.Trigger>
      <ContextMenu.Portal>
        <ContextMenu.Content
          {...portalScope}
          aria-label={`${channel.name} actions`}
          className="z-50 min-w-44 rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-md"
        >
          <Item
            onSelect={() =>
              link.current?.dispatchEvent(
                new MouseEvent("click", {
                  bubbles: true,
                  cancelable: true,
                  metaKey: true,
                  view: window,
                }),
              )
            }
          >
            Open in split
          </Item>
          <ContextMenu.Separator className="my-1 h-px bg-border" />
          <Item
            icon={channel.pinned ? "PinOff" : "Pin"}
            onSelect={() =>
              onSetState(
                { pinned: !channel.pinned },
                channel.pinned ? "Could not unpin channel" : "Could not pin channel",
              )
            }
          >
            {channel.pinned ? "Unpin" : "Pin"}
          </Item>
          <Item
            icon={channel.unread ? "MailOpen" : "Mail"}
            onSelect={() =>
              onSetState(
                channel.unread
                  ? { lastReadAt: channel.updatedAt }
                  : { markUnread: true },
                channel.unread
                  ? "Could not mark channel read"
                  : "Could not mark channel unread",
              )
            }
          >
            {channel.unread ? "Mark as read" : "Mark as unread"}
          </Item>
          <ContextMenu.Separator className="my-1 h-px bg-border" />
          <Item
            onSelect={() =>
              onSetState({ archived: true }, "Could not archive channel")
            }
          >
            Archive channel
          </Item>
        </ContextMenu.Content>
      </ContextMenu.Portal>
    </ContextMenu.Root>
  );
}

function Item({
  children,
  icon,
  onSelect,
}: {
  children: ReactNode;
  icon?: IconName;
  onSelect: () => void;
}) {
  return (
    <ContextMenu.Item
      onSelect={onSelect}
      className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-accent data-[highlighted]:text-accent-foreground"
    >
      {icon ? (
        <Icon
          name={icon}
          className="size-3.5 shrink-0 text-muted-foreground"
          aria-hidden="true"
        />
      ) : null}
      {children}
    </ContextMenu.Item>
  );
}
