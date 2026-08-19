-- See https://wiki.hypr.land/Configuring/Basics/Monitors/
-- List current monitors and supported resolutions with: hyprctl monitors all

local omarchy_gdk_scale = 2
local omarchy_monitor_scale = 2

hl.env("GDK_SCALE", tostring(omarchy_gdk_scale))

-- Desk layout: laptop on the left, Pro Display XDR as the center/primary.
hl.monitor({
  output = "desc:Apple Computer Inc ProDisplayXDR",
  mode = "preferred",
  position = "0x0",
  scale = omarchy_monitor_scale,
})

hl.monitor({
  output = "eDP-1",
  mode = "preferred",
  position = "auto-center-left",
  scale = omarchy_monitor_scale,
})

-- Any other display (or laptop-only if the XDR is unplugged).
hl.monitor({ output = "", mode = "preferred", position = "auto", scale = omarchy_monitor_scale })
