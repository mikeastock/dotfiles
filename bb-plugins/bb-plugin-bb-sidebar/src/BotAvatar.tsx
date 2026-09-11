import type { BotAvatar as BotAvatarData } from "./bots";

/**
 * A bot's face, small.
 *
 * bb-bots-sidebar draws its avatars from a colour, a silhouette, an
 * expression and an idle motion. This is a compact rendition of the first
 * three in this plugin's own geometry — enough that the same bot is
 * recognisable in both sidebars, with none of the animation: at 16px on a
 * list row, a face that moves is a face that distracts.
 *
 * The eyes are painted in the sidebar's own background colour, so they read
 * as cut-outs in both themes without a mask.
 */
export function BotAvatar({
  avatar,
  size = 16,
  className,
}: {
  avatar: BotAvatarData;
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      aria-hidden
      className={className}
      data-bot-shape={avatar.shape}
      data-bot-expression={avatar.expression}
    >
      <Silhouette shape={avatar.shape} color={avatar.color} />
      <Eyes expression={avatar.expression} />
    </svg>
  );
}

function Silhouette({
  shape,
  color,
}: {
  shape: BotAvatarData["shape"];
  color: string;
}) {
  switch (shape) {
    case "squircle":
      return <rect x="6" y="6" width="88" height="88" rx="30" fill={color} />;
    case "capsule":
      return <rect x="6" y="24" width="88" height="52" rx="26" fill={color} />;
    case "triangle":
      // Stroked in its own colour so the corners round off.
      return (
        <polygon
          points="50,10 92,88 8,88"
          fill={color}
          stroke={color}
          strokeWidth="10"
          strokeLinejoin="round"
        />
      );
    case "hexagon":
      return (
        <polygon
          points="50,6 90,28 90,72 50,94 10,72 10,28"
          fill={color}
          stroke={color}
          strokeWidth="6"
          strokeLinejoin="round"
        />
      );
    case "droplet":
      return (
        <path
          d="M50 6C68 30 86 46 86 64A36 36 0 1 1 14 64C14 46 32 30 50 6Z"
          fill={color}
        />
      );
    case "cloud":
      return (
        <g fill={color}>
          <circle cx="32" cy="58" r="22" />
          <circle cx="52" cy="44" r="26" />
          <circle cx="72" cy="60" r="20" />
          <rect x="18" y="58" width="66" height="26" rx="13" />
        </g>
      );
    case "blob":
      return (
        <path
          d="M52 6C76 4 94 24 92 48C90 72 76 94 50 94C24 94 6 74 8 48C10 24 28 8 52 6Z"
          fill={color}
        />
      );
    case "round":
    default:
      return <circle cx="50" cy="50" r="46" fill={color} />;
  }
}

/** Sixteen expressions folded into five eye styles a 16px face can carry. */
function Eyes({ expression }: { expression: BotAvatarData["expression"] }) {
  const ink = "var(--sidebar, var(--background))";
  switch (expression) {
    case "happy":
    case "laughing":
    case "proud":
      // Two upward arcs.
      return (
        <g
          fill="none"
          stroke={ink}
          strokeWidth="8"
          strokeLinecap="round"
        >
          <path d="M24 50Q34 38 44 50" />
          <path d="M56 50Q66 38 76 50" />
        </g>
      );
    case "sleepy":
    case "sad":
    case "unimpressed":
      // Two flat lines.
      return (
        <g
          fill="none"
          stroke={ink}
          strokeWidth="7"
          strokeLinecap="round"
        >
          <path d="M26 48H44" />
          <path d="M56 48H74" />
        </g>
      );
    case "focused":
    case "angry":
    case "suspicious":
      // Two bars angled in.
      return (
        <g fill={ink}>
          <path d="M24 38L44 42V52L24 50Z" />
          <path d="M56 42L76 38V50L56 52Z" />
        </g>
      );
    case "surprised":
    case "scared":
    case "excited":
      // Two wide circles.
      return (
        <g fill={ink}>
          <circle cx="35" cy="46" r="10" />
          <circle cx="65" cy="46" r="10" />
        </g>
      );
    case "curious":
    case "neutral":
    case "confused":
    case "shy":
    default:
      // Two upright ovals.
      return (
        <g fill={ink}>
          <rect x="28" y="34" width="13" height="26" rx="6.5" />
          <rect x="59" y="34" width="13" height="26" rx="6.5" />
        </g>
      );
  }
}
