import { Plugin, Store, Style } from "@opencode/plugin/gui"
import { Schema } from "effect"

// The app has no inbox API, so this follows its markup. Recent rows sit directly in the list; Needs attention and
// Archived are each a section of a header and rows, and only Needs attention holds sessions waiting on you.
const item = '[data-slot="sidebar-inbox-item"]'
const archived = `[data-slot="sidebar-inbox-scroll"] > div:has(> ${item}):not(:has([data-status="approval"], [data-status="input"]))`
const header = `${archived} > div:first-child`

export default Plugin.define({
  stores: {
    prefs: Store.global(Schema.Struct({ archivedCollapsed: Schema.Boolean }), { archivedCollapsed: true }),
  },
  setup(ctx) {
    const prefs = ctx.stores.prefs
    const collapsed = () => prefs.value.archivedCollapsed

    ctx.add(Style, () =>
      [
        `${header} { cursor: pointer; border-radius: 6px; }`,
        `${header}:hover { color: var(--v2-text-text-base); }`,
        `${header}:focus-visible { outline: none; background: var(--v2-overlay-simple-overlay-hover); }`,
        `${header} > span:first-child::after { content: attr(data-count); margin-inline-start: 6px; color: var(--v2-text-text-faint); }`,
        `${header}::after { content: ""; margin-inline: auto 4px; width: 5px; height: 5px; border-right: 1.5px solid currentColor; border-bottom: 1.5px solid currentColor; transform: rotate(${collapsed() ? "-45deg" : "45deg"}); }`,
        collapsed() ? `${archived} > ${item} { display: none; }` : "",
      ].join("\n"),
    )

    // The app renders the header as plain text and can replace it, so each new one becomes a button again.
    const mark = (isCollapsed = collapsed()) =>
      document.querySelectorAll(header).forEach((element) => {
        element.setAttribute("role", "button")
        element.setAttribute("tabindex", "0")
        element.setAttribute("aria-expanded", String(!isCollapsed))
        element.firstElementChild?.setAttribute("data-count", String(element.parentElement!.querySelectorAll(`:scope > ${item}`).length))
      })
    const toggle = (event: MouseEvent | KeyboardEvent) => {
      if (!(event.target instanceof Element) || !event.target.closest(header)) return
      if (event instanceof KeyboardEvent && event.key !== "Enter" && event.key !== " ") return
      event.preventDefault()
      const next = !collapsed()
      prefs.update((draft) => void (draft.archivedCollapsed = next))
      mark(next)
    }

    const observer = new MutationObserver(() => mark())
    observer.observe(document.body, { childList: true, subtree: true })
    mark()
    document.addEventListener("click", toggle)
    document.addEventListener("keydown", toggle)
    return () => {
      observer.disconnect()
      document.removeEventListener("click", toggle)
      document.removeEventListener("keydown", toggle)
    }
  },
})
