import { useEffect, useRef, useState, type ReactNode } from "react";
import * as ContextMenu from "@radix-ui/react-context-menu";
import * as Dialog from "@radix-ui/react-dialog";
import { useBbContext, useBbNavigate, useRpc, type PluginSidebarProject } from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { usePortalScopeProps } from "./lib/portal-scope";

const itemClass = "cursor-pointer rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-accent data-[disabled]:opacity-50";
const fieldClass = "h-9 w-full min-w-0 rounded-md border border-border bg-background px-2.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring disabled:opacity-50";
type Action = "rename" | "path" | "remove";

interface ProjectMenuState {
  items: ReactNode;
  onOpenChange: (open: boolean) => void;
  onCloseAutoFocus: (event: Event) => void;
}

export function ProjectActions({ project, children }: {
  project: PluginSidebarProject | undefined;
  children: (menu: ProjectMenuState) => ReactNode;
}) {
  if (!project || project.isPersonal) {
    return <>{children({ items: null, onOpenChange: () => {}, onCloseAutoFocus: () => {} })}</>;
  }
  return <ProjectMenu key={project.id} project={project}>{children}</ProjectMenu>;
}

function ProjectMenu({ project, children }: {
  project: PluginSidebarProject;
  children: (menu: ProjectMenuState) => ReactNode;
}) {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const navigate = useBbNavigate();
  const context = useBbContext();
  const portalScope = usePortalScopeProps();
  const [action, setAction] = useState<Action | null>(null);
  const [value, setValue] = useState("");
  const [hosts, setHosts] = useState<Array<{ id: string; name: string }> | null>(null);
  const [hostId, setHostId] = useState("");
  const [menuOpen, setMenuOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState(false);
  const submitting = useRef(false);

  useEffect(() => {
    if (!menuOpen) return;
    let canceled = false;
    setHosts(null);
    setLoadError(false);
    rpc.call("projectPathHosts", { projectId: project.id }).then(({ hosts }) => {
      if (canceled) return;
      setHosts(hosts);
      setHostId(hosts[0]?.id ?? "");
    }).catch(() => {
      if (!canceled) setLoadError(true);
    });
    return () => { canceled = true; };
  }, [menuOpen, project.id, rpc]);

  const begin = (next: Action) => {
    setValue(next === "rename" ? project.name : "");
    setAction(next);
  };
  const submit = async () => {
    if (!action || submitting.current) return;
    submitting.current = true;
    setBusy(true);
    try {
      if (action === "rename") {
        await rpc.call("renameProject", { projectId: project.id, name: value.trim() });
        toast.success("Project renamed");
      } else if (action === "path") {
        await rpc.call("addProjectPath", { projectId: project.id, hostId, path: value.trim() });
        toast.success("Local path added");
      } else {
        await rpc.call("removeProject", { projectId: project.id, confirmation: value });
        toast.success(`${project.name} removed from BB`);
        if (context.projectId === project.id) navigate.toCompose();
      }
      setAction(null);
    } catch (error) {
      toast.error("Could not update project", { description: error instanceof Error ? error.message : undefined });
    } finally {
      submitting.current = false;
      setBusy(false);
    }
  };
  const title = action === "rename" ? "Rename project" : action === "path" ? "Add local path" : "Remove project";
  const valid = action === "remove" ? value === project.name : value.trim().length > 0 && (action !== "path" || !!hostId);

  const items = <>
          <ContextMenu.Item asChild className={itemClass}>
            <a href={`/projects/${encodeURIComponent(project.id)}/settings`}>Project settings</a>
          </ContextMenu.Item>
          <ContextMenu.Separator className="my-1 h-px bg-border" />
          <ContextMenu.Item className={itemClass} onSelect={() => begin("rename")}>Rename project</ContextMenu.Item>
          {hosts === null || hosts.length > 0 ? <ContextMenu.Item className={itemClass}
            disabled={!hosts || loadError} onSelect={() => begin("path")}>
            {loadError ? "Could not load machines" : "Add local path"}
          </ContextMenu.Item> : null}
          <ContextMenu.Item className={`${itemClass} text-destructive-text`} onSelect={() => begin("remove")}>Remove project</ContextMenu.Item>
  </>;

  return <>
    {children({ items, onOpenChange: setMenuOpen, onCloseAutoFocus: (event) => { if (action) event.preventDefault(); } })}
    <Dialog.Root open={action !== null} onOpenChange={(open) => { if (!open && !busy) setAction(null); }}>
      <Dialog.Portal>
        <Dialog.Overlay {...portalScope} className="fixed inset-0 z-50 bg-black/40" />
        <Dialog.Content {...portalScope} className="fixed left-1/2 top-1/2 z-50 box-border w-[calc(100%_-_2rem)] max-w-sm -translate-x-1/2 -translate-y-1/2 rounded-xl border border-border bg-popover p-5 text-popover-foreground shadow-lg outline-none">
          <Dialog.Title className="text-sm font-semibold leading-5">{title}</Dialog.Title>
          <Dialog.Description className="mb-4 mt-1.5 text-xs leading-5 text-muted-foreground">
            {action === "remove" ? `Remove ${project.name} and all its threads? This cannot be undone. Type the project name to confirm.`
              : action === "path" ? `Choose the machine and existing folder for ${project.name}.` : `Enter a new name for ${project.name}.`}
          </Dialog.Description>
          <form onSubmit={(event) => { event.preventDefault(); if (valid) void submit(); }} className="grid gap-3">
            {action === "path" ? <label className="grid gap-1 text-xs">Machine
              <select className={fieldClass} value={hostId} disabled={busy} onChange={(event) => setHostId(event.target.value)}>
                {hosts?.map((host) => <option key={host.id} value={host.id}>{host.name}</option>)}
              </select>
            </label> : null}
            <label className="grid gap-1 text-xs">{action === "path" ? "Folder path" : "Project name"}
              <input className={fieldClass} value={value} disabled={busy} maxLength={action === "path" ? 4096 : 500}
                onChange={(event) => setValue(event.target.value)} />
            </label>
            <div className="mt-2 flex justify-end gap-2">
              <Dialog.Close asChild><button type="button" disabled={busy} className="h-8 rounded-md border border-border bg-background px-3 text-xs font-medium hover:bg-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50">Cancel</button></Dialog.Close>
              <button type="submit" disabled={busy || !valid}
                className={`h-8 rounded-md px-3 text-xs font-medium hover:opacity-90 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:opacity-50 ${action === "remove" ? "bg-destructive text-destructive-foreground" : "bg-primary text-primary-foreground"}`}>
                {busy ? "Saving..." : action === "remove" ? "Remove project" : "Save"}
              </button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  </>;
}
