import { useCallback, useEffect, useRef, useState } from "react";
import { useRealtime, useRpc } from "@get-bb/plugin-sdk/app";
import { toast } from "sonner";
import type { bbSidebarRpcContract } from "./server";
import { PROJECT_ICONS_CHANNEL } from "./project-icons";

interface ProjectSetting {
  id: string;
  name: string;
}

export function ProjectRemovalSettings() {
  const rpc = useRpc<typeof bbSidebarRpcContract>();
  const loadRequestSeq = useRef(0);
  const [projects, setProjects] = useState<ProjectSetting[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState("");
  const [pendingRemovalId, setPendingRemovalId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [removing, setRemoving] = useState(false);

  const load = useCallback(async () => {
    const seq = ++loadRequestSeq.current;
    try {
      const result = await rpc.call("listProjects", {});
      if (seq !== loadRequestSeq.current) return;
      setProjects(result.projects);
      setSelectedProjectId((current) =>
        result.projects.some((project) => project.id === current)
          ? current
          : (result.projects[0]?.id ?? ""),
      );
      setPendingRemovalId((current) =>
        result.projects.some((project) => project.id === current)
          ? current
          : null,
      );
    } catch (error) {
      if (seq !== loadRequestSeq.current) return;
      toast.error("Could not load projects", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      if (seq === loadRequestSeq.current) setLoading(false);
    }
  }, [rpc]);

  useEffect(() => {
    void load();
  }, [load]);
  useRealtime(PROJECT_ICONS_CHANNEL, () => {
    void load();
  });

  const pendingRemoval =
    projects.find((project) => project.id === pendingRemovalId) ?? null;

  const remove = async () => {
    if (!pendingRemoval || removing) return;
    const removedProject = pendingRemoval;
    loadRequestSeq.current += 1;
    setRemoving(true);
    try {
      await rpc.call("removeProject", {
        projectId: removedProject.id,
        confirmation: removedProject.name,
      });
      const remaining = projects.filter(
        (project) => project.id !== removedProject.id,
      );
      setProjects(remaining);
      setSelectedProjectId(remaining[0]?.id ?? "");
      setPendingRemovalId(null);
      toast.success(`${removedProject.name} removed from BB`);
    } catch (error) {
      toast.error("Could not remove the project", {
        description: error instanceof Error ? error.message : undefined,
      });
    } finally {
      setRemoving(false);
    }
  };

  return (
    <section aria-labelledby="settings-projects">
      <div className="mb-3">
        <h2
          id="settings-projects"
          className="text-sm font-semibold text-foreground"
        >
          Projects
        </h2>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">
          Remove projects you no longer want in BB.
        </p>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-card">
        {loading ? (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">
            Loading projects...
          </div>
        ) : projects.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-muted-foreground">
            No removable projects.
          </div>
        ) : (
          <>
            <div className="flex items-end justify-between gap-4 px-4 py-3">
              <label className="grid min-w-0 flex-1 gap-1.5 text-xs font-medium text-foreground">
                Project
                <select
                  value={selectedProjectId}
                  disabled={removing || pendingRemoval !== null}
                  onChange={(event) => {
                    setSelectedProjectId(event.target.value);
                    setPendingRemovalId(null);
                  }}
                  className="h-9 w-full rounded-md border border-border bg-background px-2.5 text-sm text-foreground outline-none focus:border-ring focus:ring-1 focus:ring-ring disabled:opacity-50"
                >
                  {projects.map((project) => (
                    <option key={project.id} value={project.id}>
                      {project.name}
                    </option>
                  ))}
                </select>
              </label>

              {!pendingRemoval ? (
                <button
                  type="button"
                  onClick={() => setPendingRemovalId(selectedProjectId)}
                  className="h-9 shrink-0 rounded-md border border-border px-3 text-sm font-medium text-destructive hover:bg-destructive/10"
                >
                  Remove...
                </button>
              ) : null}
            </div>

            {pendingRemoval ? (
              <div
                role="group"
                aria-label={`Confirm removal of ${pendingRemoval.name}`}
                className="flex flex-col gap-3 border-t border-border bg-destructive/5 px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <p className="break-words text-sm font-medium text-foreground">
                    Remove {pendingRemoval.name}?
                  </p>
                  <p className="mt-0.5 text-xs leading-5 text-muted-foreground">
                    Its threads will also be removed from BB. This cannot be
                    undone.
                  </p>
                </div>
                <div className="flex shrink-0 justify-end gap-2">
                  <button
                    type="button"
                    disabled={removing}
                    onClick={() => setPendingRemovalId(null)}
                    className="h-9 rounded-md border border-border bg-background px-3 text-sm font-medium text-foreground hover:bg-muted disabled:opacity-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    disabled={removing}
                    onClick={() => void remove()}
                    className="h-9 rounded-md bg-destructive px-3 text-sm font-medium text-destructive-foreground hover:bg-destructive/90 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {removing ? "Removing..." : "Remove from BB"}
                  </button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </div>
    </section>
  );
}
