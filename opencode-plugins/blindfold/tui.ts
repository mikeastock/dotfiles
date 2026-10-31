import { Plugin } from "@opencode/plugin/tui"
import { Blindfold, type SecretRequested } from "./rpc.js"

export default Plugin.define({
  id: "blindfold",
  setup(ctx) {
    const blindfold = ctx.client.rpc(Blindfold)
    // Requests with an open dialog in this client.
    const open = new Set<string>()

    async function answer(request: SecretRequested, options: Parameters<typeof blindfold.submit>[1]) {
      const ack = (await blindfold.ack({ requestID: request.requestID }, options)) as { accepted: boolean }
      if (!ack.accepted) return
      while (true) {
        open.add(request.requestID)
        const value = await ctx.ui.dialog.prompt({
          title: `Enter ${request.name}`,
          description: request.reason,
          placeholder: "Secret value",
        })
        // Another client answered, or the request expired, while the dialog was open.
        if (!open.delete(request.requestID)) return
        if (value === undefined) {
          await blindfold.cancel({ requestID: request.requestID }, options)
          return
        }
        // Empty submissions reopen the dialog because a value is required.
        if (value === "") continue
        const reply = (await blindfold.submit({ requestID: request.requestID, value }, options)) as { accepted: boolean }
        if (reply.accepted) ctx.ui.toast.show({ variant: "success", message: `Secret ${request.name} stored.` })
        return
      }
    }

    const stopRequested = blindfold.events.on("requested", async (event) => {
      const request = event.data as SecretRequested
      try {
        await answer(request, { location: event.location })
      } catch {
        open.delete(request.requestID)
        ctx.ui.toast.show({ variant: "error", message: `Could not send secret ${request.name}.` })
      }
    })

    const stopResolved = blindfold.events.on("resolved", (event) => {
      if (open.delete((event.data as { requestID: string }).requestID)) ctx.ui.dialog.clear()
    })

    return () => {
      stopRequested()
      stopResolved()
    }
  },
})
