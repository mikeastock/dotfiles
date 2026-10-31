import { createKeyed, Plugin } from "@opencode/plugin/gui"
import { createRoot, getOwner, onCleanup } from "solid-js"
import { Blindfold, type SecretRequested } from "./rpc.js"

export default Plugin.define({
  setup(ctx) {
    // A restarted server comes back with a new client, so listen again on each.
    createKeyed(
      () => ctx.client,
      (client) => {
        const blindfold = client.rpc(Blindfold)
        const owner = getOwner()
        // Closes the open dialog of each request this window answers.
        const open = new Map<string, () => void>()

        async function answer(request: SecretRequested, options: Parameters<typeof blindfold.submit>[1]) {
          const ack = (await blindfold.ack({ requestID: request.requestID }, options)) as { accepted: boolean }
          if (!ack.accepted) return
          // The dialog closes with its own owner, so a request answered elsewhere can close it.
          const value = await createRoot((dispose) => {
            open.set(request.requestID, dispose)
            return ctx.dialogs
              .prompt({ title: `Enter ${request.name}`, description: request.reason, placeholder: "Secret value", secret: true })
              .finally(dispose)
          }, owner)
          // Another client answered, or the request expired, while the dialog was open.
          if (!open.delete(request.requestID)) return
          if (value === undefined) {
            await blindfold.cancel({ requestID: request.requestID }, options)
            return
          }
          const reply = (await blindfold.submit({ requestID: request.requestID, value }, options)) as { accepted: boolean }
          if (reply.accepted) ctx.toast.show({ variant: "success", title: `Secret ${request.name} stored.` })
        }

        onCleanup(
          blindfold.events.on("requested", async (event) => {
            const request = event.data as SecretRequested
            try {
              await answer(request, { location: event.location })
            } catch {
              open.delete(request.requestID)
              ctx.toast.show({ variant: "error", title: `Could not send secret ${request.name}.` })
            }
          }),
        )
        onCleanup(
          blindfold.events.on("resolved", (event) => {
            const requestID = (event.data as { requestID: string }).requestID
            const close = open.get(requestID)
            open.delete(requestID)
            close?.()
          }),
        )
      },
    )
  },
})
