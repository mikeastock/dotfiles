-- See https://wiki.hypr.land/Configuring/Basics/Monitors/
-- List current monitors and supported resolutions with: hyprctl monitors all

local omarchy_gdk_scale = 2
local omarchy_monitor_scale = 1.6

hl.env("GDK_SCALE", tostring(omarchy_gdk_scale))

-- Positions use scaled size, so changing omarchy_monitor_scale cannot overlap
-- the screens (overlap makes the cursor appear on both at once).
local function logical(px)
  return math.floor(px / omarchy_monitor_scale + 0.5)
end

local xdr_w, xdr_h = logical(6016), logical(3384)
local laptop_h = logical(2000)

-- XDR on the left; laptop against its right edge, bottoms aligned.
hl.monitor({
  output = "desc:Apple Computer Inc ProDisplayXDR",
  mode = "preferred",
  position = "0x0",
  scale = omarchy_monitor_scale,
})

hl.monitor({
  output = "eDP-1",
  mode = "preferred",
  position = string.format("%dx%d", xdr_w, xdr_h - laptop_h),
  scale = omarchy_monitor_scale,
})

-- Any other display (or laptop-only if the XDR is unplugged).
hl.monitor({ output = "", mode = "preferred", position = "auto", scale = omarchy_monitor_scale })
