-- Written by `oma-cast setup hyprland`, then edited by hand; rerunning setup overwrites it.
-- The binding reaches the plugin's global shortcut directly, so no process
-- starts per keypress.

-- Super+Space opens oma-cast (replaces Omarchy's menu, which is still
-- reachable from inside oma-cast as "Omarchy Menu").
o.rebind("SUPER + SPACE", "oma-cast launcher", hl.dsp.global("oma-cast:toggle"))
