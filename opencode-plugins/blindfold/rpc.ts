import { Rpc } from "@opencode/plugin/rpc"

const request = {
  type: "object",
  properties: { requestID: { type: "string" } },
  required: ["requestID"],
  additionalProperties: false,
} as const

const reply = {
  type: "object",
  properties: { accepted: { type: "boolean" } },
  required: ["accepted"],
  additionalProperties: false,
} as const

export const Blindfold = Rpc.define({
  id: "blindfold",
  methods: {
    submit: {
      input: {
        type: "object",
        properties: {
          requestID: { type: "string" },
          value: { type: "string", minLength: 1 },
        },
        required: ["requestID", "value"],
        additionalProperties: false,
      },
      output: reply,
    },
    ack: { input: request, output: reply },
    cancel: { input: request, output: reply },
  },
  events: {
    requested: {
      schema: {
        type: "object",
        properties: {
          requestID: { type: "string" },
          sessionID: { type: "string" },
          name: { type: "string" },
          reason: { type: "string" },
        },
        required: ["requestID", "sessionID", "name", "reason"],
        additionalProperties: false,
      },
    },
    resolved: { schema: request },
  },
})

export type SecretRequested = {
  requestID: string
  sessionID: string
  name: string
  reason: string
}
