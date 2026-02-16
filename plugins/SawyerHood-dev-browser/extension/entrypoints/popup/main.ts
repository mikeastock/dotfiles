import type { GetStateMessage, SetStateMessage, StateResponse } from "../../utils/types";

const toggle = document.getElementById("active-toggle") as HTMLInputElement;
const statusText = document.getElementById("status-text") as HTMLSpanElement;
const connectionStatus = document.getElementById("connection-status") as HTMLParagraphElement;

function updateUI(state: StateResponse): void {
  toggle.checked = state.isActive;
  statusText.textContent = state.isActive ? "Active" : "Inactive";

  if (state.isActive) {
    connectionStatus.textContent = state.isConnected ? "Connected to relay" : "Connecting...";
    connectionStatus.className = state.isConnected
      ? "connection-status connected"
      : "connection-status connecting";
  } else {
    connectionStatus.textContent = "";
    connectionStatus.className = "connection-status";
  }
}

function refreshState(): void {
  chrome.runtime.sendMessage<GetStateMessage, StateResponse>({ type: "getState" }, (response) => {
    if (response) {
      updateUI(response);
    }
  });
}

// Load initial state
refreshState();

// Poll for state updates while popup is open
const pollInterval = setInterval(refreshState, 1000);

// Clean up on popup close
window.addEventListener("unload", () => {
  clearInterval(pollInterval);
});

// Handle toggle changes
toggle.addEventListener("change", () => {
  const isActive = toggle.checked;
  chrome.runtime.sendMessage<SetStateMessage, StateResponse>(
    { type: "setState", isActive },
    (response) => {
      if (response) {
        updateUI(response);
      }
    }
  );
});
