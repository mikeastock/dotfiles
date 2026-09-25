import { HugeiconsIcon, type IconSvgElement } from "@hugeicons/react";
import {
  ArrowDown01Icon,
  ArrowLeft01Icon,
  ArrowRight01Icon,
  ArrowTurnBackwardIcon,
  ArrowUp01Icon,
  ArrowUpDownIcon,
  CancelCircleIcon,
  Car05Icon,
  CheckListIcon,
  Clock01Icon,
  ComputerIcon,
  ComputerTerminal01Icon,
  Mail01Icon,
  MailOpen01Icon,
  Edit02Icon,
  FolderGitIcon,
  GitBranchIcon,
  HelpCircleIcon,
  Loading03Icon,
  PauseCircleIcon,
  PinIcon,
  PinOffIcon,
  PlugSocketIcon,
  Pulse01Icon,
  Search01Icon,
  Target02Icon,
  Tick02Icon,
  UserAdd01Icon,
  WorkflowCircle03Icon,
  Yoga02Icon,
} from "@hugeicons/core-free-icons";
import { cn } from "../lib/utils";

const ICON_MAP = {
  ArrowTurnBackward: ArrowTurnBackwardIcon,
  ArrowUpDown: ArrowUpDownIcon,
  Car: Car05Icon,
  Check: Tick02Icon,
  ChevronDown: ArrowDown01Icon,
  ChevronLeft: ArrowLeft01Icon,
  ChevronRight: ArrowRight01Icon,
  ChevronUp: ArrowUp01Icon,
  CircleQuestion: HelpCircleIcon,
  CircleX: CancelCircleIcon,
  Clock: Clock01Icon,
  Computer: ComputerIcon,
  Edit: Edit02Icon,
  FolderGit: FolderGitIcon,
  GitBranch: GitBranchIcon,
  ListTodo: CheckListIcon,
  Loading: Loading03Icon,
  Mail: Mail01Icon,
  MailOpen: MailOpen01Icon,
  Meditation: Yoga02Icon,
  PauseCircle: PauseCircleIcon,
  Pin: PinIcon,
  PinOff: PinOffIcon,
  Plug: PlugSocketIcon,
  Pulse: Pulse01Icon,
  Search: Search01Icon,
  Target: Target02Icon,
  Terminal: ComputerTerminal01Icon,
  UserRoundPlus: UserAdd01Icon,
  Workflow: WorkflowCircle03Icon,
} as const satisfies Record<string, IconSvgElement>;

export type IconName = keyof typeof ICON_MAP;

export function Icon({
  name,
  className,
  "aria-hidden": ariaHidden,
  "aria-label": ariaLabel,
}: {
  name: IconName;
  className?: string;
  "aria-hidden"?: boolean | "true" | "false";
  "aria-label"?: string;
}) {
  return (
    <HugeiconsIcon
      icon={ICON_MAP[name]}
      className={cn(className)}
      aria-hidden={ariaHidden}
      aria-label={ariaLabel}
      data-icon={name}
    />
  );
}
