// bb-plugin-diffr frontend: a Diffr tab in each thread's right panel, opened
// from the panel launcher, the thread header, or the command palette.
import { definePluginApp, useBbNavigate, type PluginThreadHeaderActionProps } from "@get-bb/plugin-sdk/app";
import { Icon } from "@/components/ui/icon";
import { DiffrPanel } from "./src/app/DiffrPanel";

const ACTION_ID = "diffr";

function HeaderButton(_props: PluginThreadHeaderActionProps) {
  const navigate = useBbNavigate();
  return (
    <button
      type="button"
      aria-label="Open diffr"
      title="Open diffr"
      onClick={() => navigate.openThreadPanel({ actionId: ACTION_ID })}
      className="flex size-7 items-center justify-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
    >
      <Icon name="FileDiff" className="size-4" />
    </button>
  );
}

export default definePluginApp((app) => {
  app.slots.threadPanelAction({
    id: ACTION_ID,
    title: "Diffr",
    icon: "FileDiff",
    layout: "flush",
    component: DiffrPanel,
  });
  app.slots.experimental_threadHeaderAction({
    id: "open",
    title: "Diffr",
    component: HeaderButton,
  });
  app.commands.register({
    id: "open",
    title: "Diffr: open structural diff",
    isAvailable: ({ threadId }) => threadId !== null,
    run: ({ openPanel }) => {
      openPanel({ actionId: ACTION_ID });
    },
  });
});
