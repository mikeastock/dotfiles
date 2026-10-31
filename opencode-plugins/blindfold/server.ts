import { execFile, type ExecFileException } from "node:child_process"
import { randomUUID } from "node:crypto"
import { Plugin } from "@opencode/plugin"
import { Error as ToolError, type Result } from "@opencode/plugin/promise/tool"
import { Redactor } from "./redact.js"
import { Blindfold } from "./rpc.js"

const NAMESPACE = "blindfold"
const GET_TOOL = "get"
const GET_TOOL_IDS = new Set([`${NAMESPACE}_${GET_TOOL}`, `${NAMESPACE}.${GET_TOOL}`])
const NAME_PATTERN = "^[A-Z_][A-Z0-9_]*$"
const PROMPT_TIMEOUT = 10 * 60_000
const ACK_TIMEOUT = 5_000
const ONEPASSWORD_PREFIX = "op://"
// Long enough for 1Password to ask the user to unlock it.
const ONEPASSWORD_TIMEOUT = 2 * 60_000
const ONEPASSWORD_ACCOUNT = "my.1password.com"

type Answer = { status: "submitted"; value: string } | { status: "cancelled" | "timeout" | "unavailable" }
type Pending = { finish: (answer: Answer) => void; acknowledge: () => void }

function failure(name: string, status: Exclude<Answer["status"], "submitted">) {
  if (status === "cancelled") return `The user declined to provide ${name}.`
  if (status === "timeout") return `Timed out waiting for the user to provide ${name}.`
  return [
    `No OpenCode TUI with opencode-blindfold responded, so the user could not be asked for ${name}.`,
    "Ask the user to add opencode-blindfold to plugins in ~/.config/opencode/cli.json and restart the TUI.",
  ].join(" ")
}

type Settings = {
  shell: { enabled: boolean; approve: boolean }
  codemode: { enabled: boolean }
  secrets: Map<string, string>
  onepassword: { account?: string }
}

function group(options: Record<string, unknown>, key: string) {
  const value = options[key]
  if (value === undefined) return {}
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`opencode-blindfold ${key} option must be an object`)
  }
  return value as Record<string, unknown>
}

function boolean(options: Record<string, unknown>, key: string, name: string, fallback: boolean) {
  const value = options[name]
  if (value === undefined) return fallback
  if (typeof value !== "boolean") throw new Error(`opencode-blindfold ${key}.${name} option must be a boolean`)
  return value
}

function getSecrets(options: Record<string, unknown>) {
  const secrets = new Map<string, string>()
  for (const [name, value] of Object.entries(group(options, "secrets"))) {
    if (!new RegExp(NAME_PATTERN).test(name)) throw new Error(`opencode-blindfold secrets names must match ${NAME_PATTERN}, got ${name}`)
    if (typeof value !== "string") throw new Error(`opencode-blindfold secrets.${name} option must be a string`)
    secrets.set(name, value)
  }
  return secrets
}

function getOnePassword(options: Record<string, unknown>) {
  const account = group(options, "1password").account
  if (account === undefined) return {}
  if (typeof account !== "string" || account === "") throw new Error("opencode-blindfold 1password.account option must be a non-empty string")
  return { account }
}

function getSettings(options: Record<string, unknown>): Settings {
  const shell = group(options, "shell")
  const codemode = group(options, "codemode")
  const settings = {
    shell: { enabled: boolean(shell, "shell", "enabled", true), approve: boolean(shell, "shell", "approve", true) },
    codemode: { enabled: boolean(codemode, "codemode", "enabled", true) },
    secrets: getSecrets(options),
    onepassword: getOnePassword(options),
  }
  if (!settings.shell.enabled && !settings.codemode.enabled) {
    throw new Error("opencode-blindfold needs shell.enabled or codemode.enabled, otherwise secrets cannot be used")
  }
  return settings
}

// Secret names are environment-variable style, so a word match covers $NAME, ${NAME}, os.environ["NAME"], and so on.
function mentioned(names: string[], command: string) {
  return names.filter((name) => new RegExp(`(?<![A-Za-z0-9_])${name}(?![A-Za-z0-9_])`).test(command))
}

function opRead(reference: string, account: string | undefined) {
  const args = ["read", "--no-newline", ...(account ? ["--account", account] : []), reference]
  return new Promise<{ error: ExecFileException | null; stdout: string; stderr: string }>((resolve) => {
    execFile("op", args, { timeout: ONEPASSWORD_TIMEOUT }, (error, stdout, stderr) => resolve({ error, stdout, stderr }))
  })
}

async function readOnePassword(name: string, reference: string, account: string | undefined) {
  let { error, stdout, stderr } = await opRead(reference, account)
  // With one account signed in, op picks it on its own; with several, fall back to the personal account.
  if (error && account === undefined && stderr.includes("multiple accounts found")) {
    ;({ error, stdout, stderr } = await opRead(reference, ONEPASSWORD_ACCOUNT))
  }
  const fail = (detail: string) => new Error(`Couldn't read ${name} from 1Password (${reference}): ${detail}`)
  if (error && (error as NodeJS.ErrnoException).code === "ENOENT") throw fail("the 1Password CLI (op) isn't installed.")
  if (error && error.killed) throw fail("timed out waiting for 1Password. Check that it's unlocked.")
  if (error) throw fail(stderr.trim() || error.message)
  if (stdout === "") throw fail("the field is empty.")
  return stdout
}

function instructions(settings: Settings) {
  const call = settings.codemode.enabled ? "`tools.blindfold.get({ name, reason })` in Code Mode" : "the `blindfold_get` tool"
  return [
    `When a task needs a secret such as an API key, token, or password, call ${call}; it asks the user privately if the secret isn't stored yet.`,
    settings.secrets.size > 0 ? `The user has configured these secrets: ${[...settings.secrets.keys()].join(", ")}.` : undefined,
    "Never ask the user to paste secrets into the chat.",
    "Secret values are redacted from tool output, so you won't see them even if you print them; you'll see `[REDACTED:NAME]` instead.",
  ].filter(Boolean).join(" ")
}

function shellUsage(settings: Settings) {
  if (!settings.shell.enabled) return []
  return [
    "Shell commands receive it as an environment variable only when the command names it; pass it explicitly to programs that expect another variable, e.g. `GH_TOKEN=\"$GITHUB_TOKEN\" gh api user`.",
    settings.shell.approve ? "The user must approve each such command." : undefined,
  ]
}

function getDescription(settings: Settings) {
  return [
    "Get a secret such as an API token or password. If it isn't stored yet, the user is asked to enter it privately.",
    settings.codemode.enabled
      ? "Returns the value to the running code only; use it directly, e.g. in a fetch header."
      : "The value is never returned to you.",
    ...shellUsage(settings),
  ].filter(Boolean).join(" ")
}

const NAME_INPUT = {
  type: "string",
  pattern: NAME_PATTERN,
  description: "Environment-variable style name, e.g. GITHUB_TOKEN",
} as const

export default Plugin.define({
  id: "blindfold",
  async setup(ctx) {
    const settings = getSettings(ctx.options)
    const redactor = new Redactor()
    const pending = new Map<string, Pending>()

    // Plain values are known upfront, so they're redacted and reach shell commands before any get.
    for (const [name, source] of settings.secrets) {
      if (source !== "" && !source.startsWith(ONEPASSWORD_PREFIX)) redactor.set(name, source)
    }

    const rpc = await ctx.rpc.register(Blindfold, {
      submit: async (input) => {
        const { requestID, value } = input as { requestID: string; value: string }
        const request = pending.get(requestID)
        if (!request || value === "") return { accepted: false }
        request.finish({ status: "submitted", value })
        return { accepted: true }
      },
      ack: async (input) => {
        const request = pending.get((input as { requestID: string }).requestID)
        if (!request) return { accepted: false }
        request.acknowledge()
        return { accepted: true }
      },
      cancel: async (input) => {
        const request = pending.get((input as { requestID: string }).requestID)
        if (!request) return { accepted: false }
        request.finish({ status: "cancelled" })
        return { accepted: true }
      },
    })

    function ask(request: { sessionID: string; name: string; reason: string }) {
      const requestID = randomUUID()
      return new Promise<Answer>((resolve) => {
        let acknowledged = false
        const finish = (answer: Answer) => {
          if (!pending.delete(requestID)) return
          clearTimeout(timer)
          clearTimeout(ackTimer)
          resolve(answer)
          void rpc.events.emit("resolved", { requestID }).catch(() => undefined)
        }
        const timer = setTimeout(() => finish({ status: acknowledged ? "timeout" : "unavailable" }), PROMPT_TIMEOUT)
        const ackTimer = setTimeout(() => finish({ status: "unavailable" }), ACK_TIMEOUT)
        pending.set(requestID, {
          finish,
          acknowledge: () => {
            acknowledged = true
            clearTimeout(ackTimer)
          },
        })
        rpc.events.emit("requested", { requestID, ...request }).catch(() => finish({ status: "unavailable" }))
      })
    }

    // The TUI shows one dialog at a time and a new prompt closes the open one, so prompts must not overlap.
    let queue: Promise<unknown> = Promise.resolve()
    function serial<T>(task: () => Promise<T>) {
      const next = queue.then(task, task)
      queue = next.catch(() => undefined)
      return next
    }

    async function obtain(request: { sessionID: string; name: string; reason: string; replace?: boolean }) {
      const { name, reason, replace } = request
      if (!new RegExp(NAME_PATTERN).test(name)) throw new Error(`Secret name must match ${NAME_PATTERN}`)
      const stored = redactor.get(name)
      if (stored !== undefined && !replace) return stored
      return serial(async () => {
        // Another call may have stored it while this one waited.
        const stored = redactor.get(name)
        if (stored !== undefined && !replace) return stored
        const value = await resolve({ sessionID: request.sessionID, name, reason })
        redactor.set(name, value)
        return value
      })
    }

    async function resolve(request: { sessionID: string; name: string; reason: string }) {
      const { name } = request
      const source = settings.secrets.get(name)
      if (source === undefined) {
        const answer = await ask(request)
        if (answer.status !== "submitted") throw new Error(failure(name, answer.status))
        return answer.value
      }
      if (source === "") throw new Error(`${name} is empty in the opencode-blindfold secrets option, for example because its {env:...} variable isn't set.`)
      if (source.startsWith(ONEPASSWORD_PREFIX)) return readOnePassword(name, source, settings.onepassword.account)
      return source
    }

    await ctx.tool.transform((editor) => {
      editor.namespace({
        name: NAMESPACE,
        description: "Secrets provided by the user without revealing their values to the agent.",
      })
      editor.add({
        name: GET_TOOL,
        description: getDescription(settings),
        input: {
          type: "object",
          properties: {
            name: NAME_INPUT,
            reason: { type: "string", minLength: 1, description: "Why the secret is needed, shown to the user if it must be entered" },
            replace: { type: "boolean", description: "Ask the user again even if the secret is already stored" },
          },
          required: ["name"],
          additionalProperties: false,
        },
        // In Code Mode the value reaches only the running code. As a regular tool the result enters the chat,
        // so it confirms the secret is stored without returning it.
        options: settings.codemode.enabled
          ? { namespace: NAMESPACE, codemode: true, pinned: true }
          : { namespace: NAMESPACE, codemode: false },
        async execute(input, context) {
          const { name, reason, replace } = input as { name: string; reason?: string; replace?: boolean }
          await context.progress({ title: `Secret ${name}` })
          const value = await obtain({ sessionID: context.sessionID, name, reason: reason ?? `The agent needs ${name}.`, replace })
          if (settings.codemode.enabled) return { content: value }
          return {
            content: `Secret ${name} is stored. Blindfold secrets available: ${redactor.names().join(", ")}.`,
            metadata: { title: `Secret ${name}`, name },
          }
        },
      })
    })

    await ctx.tool.hook("execute.after", (event) => {
      if (redactor.size === 0 || GET_TOOL_IDS.has(event.tool)) return
      if (event.status === "completed") {
        event.result = redactor.value(event.result as Record<string, unknown>) as Result
        return
      }
      const message = redactor.text(event.error.message)
      const metadata = redactor.value(event.error.metadata)
      if (message === event.error.message && metadata === event.error.metadata) return
      const cause = redactor.text(String(event.error.error)) === String(event.error.error) ? event.error.error : undefined
      event.error = new ToolError({ message, metadata, error: cause })
    })

    const system = instructions(settings)
    await ctx.session.hook("context", (event) => {
      if (redactor.size > 0) {
        event.messages = redactor.value(event.messages)
        event.system = redactor.value(event.system)
      }
      event.system.push({ type: "text", text: system })
    })

    // Last line of defense for requests that bypass the context hook, such as compaction and titles.
    await ctx.session.hook("http.request", async (event) => {
      if (redactor.size === 0 || !event.request.body) return
      const body = await event.request.clone().text()
      const redacted = redactor.text(body)
      if (redacted === body) return
      const headers = new Headers(event.request.headers)
      headers.delete("content-length")
      event.request = new Request(event.request, { body: redacted, headers })
    })

    if (settings.shell.enabled) {
      // Commands can only read secrets they name, so naming one is what triggers approval.
      if (settings.shell.approve) {
        await ctx.permission.hook("evaluate", (event) => {
          if (event.action !== "shell" || event.effect === "deny") return
          const names = [...new Set(event.resources.flatMap((command) => mentioned(redactor.names(), command)))]
          if (names.length === 0) return
          event.effect = "ask"
          event.message = `This command can read ${names.join(", ")}`
        })
      }
      await ctx.shell.hook("create.before", (event) => {
        for (const name of mentioned(redactor.names(), event.command)) event.env[name] = redactor.get(name)
      })
    }

    return () => {
      for (const request of pending.values()) request.finish({ status: "unavailable" })
    }
  },
})
