// BB Sidebar: a shelved, manually ordered replacement for bb's thread list.
// Manual order stays fixed until the user moves a row. Optional views can sort
// by activity, creation date, or project without changing the saved order.
import { definePluginApp } from "@get-bb/plugin-sdk/app";
import "./src/theme.css";
import { ThreadInbox } from "./src/ThreadInbox";
import { ParentChip } from "./src/ParentChip";
import { SubagentsChip } from "./src/SubagentsChip";
import { SidebarSettings } from "./src/SidebarSettings";

export default definePluginApp((app) => {
  app.slots.settingsSection({
    id: "sidebar-settings",
    component: SidebarSettings,
  });

  app.slots.experimental_threadList({
    id: "inbox",
    title: "BB Sidebar",
    description:
      "Shelves, project filtering, manual ordering, and optional sorted views.",
    component: ThreadInbox,
  });

  // Registered first, so it renders on the left of the children chip: the
  // header then reads up (parent) then down (children).
  //
  // The hidden child is otherwise a dead end — it is not in the list, so this
  // chip is its only route back to the parent.
  app.slots.experimental_threadHeaderAction({
    id: "parent",
    title: "Parent thread",
    component: ParentChip,
  });

  // A flat inbox has nowhere to nest child threads, so the list hides them
  // and this chip gives them a home on their parent's header.
  app.slots.experimental_threadHeaderAction({
    id: "children",
    title: "Child threads",
    component: SubagentsChip,
  });
});
