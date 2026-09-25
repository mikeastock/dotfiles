import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent as ReactKeyboardEvent,
} from "react";
import type { PluginSidebarProject } from "@get-bb/plugin-sdk/app";
import { Icon } from "./components/Icon";
import { Popover, PopoverContent, PopoverTrigger } from "./components/Popover";
import { ProjectFavicon } from "./ProjectFavicon";
import { projectIconUrl } from "./project-icons";
import { ALL_PROJECTS, filterProjectsByName } from "./inbox";
import { cn } from "./lib/utils";

const ALL_PROJECTS_LABEL = "All projects";
const LISTBOX_ID = "bb-sidebar-project-scope-list";
const optionId = (index: number) => `${LISTBOX_ID}-option-${index}`;

interface ScopeOption {
  id: string;
  name: string;
}

/**
 * Project scope picker. The card opens with a filter field in its first row, so
 * a long project list stays reachable by typing instead of scrolling.
 */
export function ProjectScopeSelect({
  scope,
  projects,
  projectIconRevision,
  onScopeChange,
}: {
  scope: string;
  projects: readonly PluginSidebarProject[];
  projectIconRevision: number;
  onScopeChange: (scope: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  const options = useMemo<ScopeOption[]>(
    () => [
      { id: ALL_PROJECTS, name: ALL_PROJECTS_LABEL },
      ...projects.map((project) => ({ id: project.id, name: project.name })),
    ],
    [projects],
  );
  const matches = useMemo(
    () => filterProjectsByName(options, query),
    [options, query],
  );
  const scopeLabel =
    options.find((option) => option.id === scope)?.name ?? ALL_PROJECTS_LABEL;
  // The highlight follows the list as filtering shrinks it under the cursor.
  const highlighted =
    matches.length === 0 ? -1 : Math.min(activeIndex, matches.length - 1);

  useEffect(() => {
    if (!open || highlighted < 0) return;
    listRef.current
      ?.querySelector(`[data-scope-option="${highlighted}"]`)
      ?.scrollIntoView({ block: "nearest" });
  }, [highlighted, open]);

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen);
    setQuery("");
    if (nextOpen) {
      const current = options.findIndex((option) => option.id === scope);
      setActiveIndex(current < 0 ? 0 : current);
    }
  };

  const select = (optionId: string) => {
    onScopeChange(optionId);
    handleOpenChange(false);
  };

  const handleTriggerKeyDown = (event: ReactKeyboardEvent<HTMLElement>) => {
    if (open) return;
    if (["Enter", " ", "ArrowDown", "ArrowUp"].includes(event.key)) {
      // Swallowing the key stops the browser from turning it into a click that
      // would toggle the card shut again.
      event.preventDefault();
      handleOpenChange(true);
    }
  };

  const handleQueryKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (matches.length === 0) return;
      const step = event.key === "ArrowDown" ? 1 : -1;
      setActiveIndex((highlighted + step + matches.length) % matches.length);
      return;
    }
    if (event.key === "Home" || event.key === "End") {
      event.preventDefault();
      setActiveIndex(event.key === "Home" ? 0 : matches.length - 1);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const option = matches[highlighted];
      if (option) select(option.id);
    }
  };

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      {/* Ghost trigger: no border, no filled track — it reads as a label
          until you hover it. */}
      <PopoverTrigger asChild>
        <button
          type="button"
          aria-haspopup="listbox"
          aria-expanded={open}
          aria-label={`Project scope: ${scopeLabel}`}
          onKeyDown={handleTriggerKeyDown}
          className="flex h-7 min-w-0 flex-1 items-center justify-between gap-1 whitespace-nowrap rounded-md px-1.5 py-1 text-xs font-medium text-muted-foreground outline-none transition-colors duration-150 hover:bg-sidebar-accent hover:duration-0"
        >
          <span className="flex min-w-0 items-center gap-1.5">
            {scope !== ALL_PROJECTS ? (
              <ProjectFavicon
                src={projectIconUrl(scope, projectIconRevision)}
                className="size-3"
              />
            ) : null}
            <span className="truncate">{scopeLabel}</span>
          </span>
          <Icon name="ChevronDown" className="size-4 shrink-0 opacity-50" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-[var(--radix-popover-trigger-width)] min-w-48 p-0">
        <div className="flex items-center gap-1.5 border-b border-border px-2">
          <Icon
            name="Search"
            className="size-3 shrink-0 opacity-50"
            aria-hidden="true"
          />
          <input
            role="combobox"
            aria-label="Filter projects"
            aria-expanded
            aria-autocomplete="list"
            aria-controls={LISTBOX_ID}
            aria-activedescendant={
              highlighted < 0 ? undefined : optionId(highlighted)
            }
            value={query}
            placeholder="Filter projects"
            onChange={(event) => {
              setQuery(event.target.value);
              setActiveIndex(0);
            }}
            onKeyDown={handleQueryKeyDown}
            className="h-8 w-full bg-transparent text-xs text-foreground outline-none placeholder:text-muted-foreground"
          />
        </div>
        <div
          ref={listRef}
          id={LISTBOX_ID}
          role="listbox"
          aria-label="Projects"
          className="max-h-72 overflow-y-auto p-1"
        >
          {matches.length === 0 ? (
            <p className="px-2 py-3 text-center text-xs text-muted-foreground">
              No projects found
            </p>
          ) : (
            matches.map((option, index) => (
              <div
                key={option.id}
                id={optionId(index)}
                data-scope-option={index}
                role="option"
                aria-selected={option.id === scope}
                onPointerMove={() => setActiveIndex(index)}
                onClick={() => select(option.id)}
                className={cn(
                  "relative flex w-full cursor-default select-none items-center rounded-sm py-1.5 pl-2 pr-8 text-xs outline-none",
                  index === highlighted && "bg-state-hover text-foreground",
                )}
              >
                <span className="flex min-w-0 items-center gap-1.5">
                  {option.id !== ALL_PROJECTS ? (
                    <ProjectFavicon
                      src={projectIconUrl(option.id, projectIconRevision)}
                      className="size-3"
                    />
                  ) : null}
                  <span className="truncate">{option.name}</span>
                </span>
                {option.id === scope ? (
                  <span className="absolute right-2 flex size-3.5 items-center justify-center">
                    <Icon name="Check" className="size-4" />
                  </span>
                ) : null}
              </div>
            ))
          )}
        </div>
      </PopoverContent>
    </Popover>
  );
}
