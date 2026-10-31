type Needle = { text: string; replacement: string }

// Shorter encodings are too likely to match unrelated output, such as short hex runs.
const MIN_ENCODED_LENGTH = 8

// Common encodings an agent might produce without meaning to reveal the value.
function encodings(value: string) {
  const bytes = Buffer.from(value)
  return [
    JSON.stringify(value).slice(1, -1),
    encodeURIComponent(value),
    bytes.toString("base64").replace(/=+$/, ""),
    bytes.toString("base64url"),
    bytes.toString("hex"),
  ]
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

export function replacement(name: string) {
  return `[REDACTED:${name}]`
}

export class Redactor {
  #secrets = new Map<string, string>()
  #needles: Needle[] = []

  get size() {
    return this.#secrets.size
  }

  names() {
    return [...this.#secrets.keys()]
  }

  entries() {
    return [...this.#secrets.entries()]
  }

  get(name: string) {
    return this.#secrets.get(name)
  }

  set(name: string, value: string) {
    if (value === "") throw new Error("Secrets must not be empty")
    this.#secrets.set(name, value)
    this.#rebuild()
  }

  delete(name: string) {
    const deleted = this.#secrets.delete(name)
    if (deleted) this.#rebuild()
    return deleted
  }

  text(input: string) {
    let output = input
    for (const needle of this.#needles) {
      if (output.includes(needle.text)) output = output.replaceAll(needle.text, needle.replacement)
    }
    return output
  }

  /** Redacts strings nested in plain objects and arrays, preserving references when nothing changes. */
  value<T>(input: T): T {
    if (this.#needles.length === 0) return input
    return this.#walk(input) as T
  }

  #walk(input: unknown): unknown {
    if (typeof input === "string") return this.text(input)
    if (Array.isArray(input)) {
      let changed = false
      const output = input.map((item) => {
        const next = this.#walk(item)
        if (next !== item) changed = true
        return next
      })
      return changed ? output : input
    }
    if (isPlainObject(input)) {
      let changed = false
      const output: Record<string, unknown> = {}
      for (const [key, item] of Object.entries(input)) {
        const next = this.#walk(item)
        if (next !== item) changed = true
        output[key] = next
      }
      return changed ? output : input
    }
    return input
  }

  #rebuild() {
    const needles = new Map<string, string>()
    for (const [name, value] of this.#secrets) {
      if (!needles.has(value)) needles.set(value, replacement(name))
      for (const text of encodings(value)) {
        if (text.length >= MIN_ENCODED_LENGTH && !needles.has(text)) needles.set(text, replacement(name))
      }
    }
    this.#needles = [...needles]
      .map(([text, replacement]) => ({ text, replacement }))
      .sort((a, b) => b.text.length - a.text.length)
  }
}
