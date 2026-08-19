-- Keep only your personal keybinding overrides here. Add new bindings or
-- unbind defaults before replacing them.

-- See current bindings and descriptions:
--   omarchy menu keybindings --print

-- To disable every Omarchy default binding, set this in
-- ~/.config/hypr/hyprland.lua before require("default.hypr.omarchy"), then add
-- only the bindings you want below:
--   omarchy_default_bindings = false

-- To disable all preinstalled app/webapp bindings, set:
--   omarchy_preinstalled_bindings = false

-- Add a new binding.
-- o.bind("SUPER + SHIFT + R", "SSH", "alacritty -e ssh your-server")

-- Change an existing binding by unbinding it first, then binding the key again.
-- This example changes SUPER+SPACE from the launcher to the Omarchy root menu.
-- hl.unbind("SUPER + SPACE")
-- o.bind("SUPER + SPACE", "Omarchy menu", "omarchy-menu toggle root")

-- SUPER+F was exclusive compositor fullscreen. Maximize in the layout
-- instead (fill the working area, keep the bar). Do not tell the client
-- it is fullscreen — Chromium/Helium would only hide browser chrome.
-- Exclusive fullscreen remains on SUPER+CTRL+F.
hl.unbind("SUPER + F")
hl.unbind("SUPER + CTRL + F")
o.bind("SUPER + F", "Tiled full screen", hl.dsp.window.fullscreen_state({ internal = 1, client = 0, action = "toggle" }))
o.bind("SUPER + CTRL + F", "Full screen", hl.dsp.window.fullscreen({ mode = "fullscreen" }))

-- Moonlander Meh (Ctrl+Shift+Alt) + W. wev also reports the Shift key as Caps_Lock.
-- Hold to record, release to transcribe.
local voxtype_ptt_keys = {
  "CTRL + SHIFT + ALT + W",
  "CTRL + ALT + CAPS + W",
  "CTRL + SHIFT + ALT + CAPS + W",
}
local voxtype_ptt_opts = {
  dont_inhibit = true,
  allow_input_capture = true,
  transparent = true,
}
for _, keys in ipairs(voxtype_ptt_keys) do
  o.bind(keys, "Start dictation (push-to-talk)", "voxtype record start", voxtype_ptt_opts)
  o.bind(keys, "Stop dictation (push-to-talk)", "voxtype record stop", {
    release = true,
    dont_inhibit = true,
    allow_input_capture = true,
    transparent = true,
  })
end
