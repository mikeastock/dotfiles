import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { registerContextCommand } from "./context";

export * from "./tokens";
export * from "./grid";
export * from "./breakdown";

export default function (pi: ExtensionAPI) {
  registerContextCommand(pi);
}
