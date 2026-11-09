import type { Rpc } from "@opencode/plugin/rpc"

// Shared by the server plugin and the GUI. Type-only import: the definition is plain data, so the server plugin needs
// no OpenCode packages at runtime (the host provides them). Input is validated here and again by the handlers.
const output = {} as const
const object = (properties: Record<string, unknown>, required: string[] = []) =>
  ({ type: "object", properties, required, additionalProperties: false }) as const
const sessionID = { type: "string", minLength: 1, maxLength: 200 }
const effect = { enum: ["allow", "ask", "deny", null] }

export const MachinesRpc = {
  id: "oc-machine.admin",
  methods: {
    state: { input: object({ sessionID }), output },
    setCells: {
      input: object({
        expectedRevision: { type: "integer", minimum: 0 },
        sessionID,
        changes: {
          type: "array", maxItems: 200,
          items: object({
            entity: { type: "string" }, capability: { type: "string" }, effect,
            agent: { type: "string" }, session: { type: "boolean" },
          }, ["entity", "capability", "effect"]),
        },
      }, ["changes"]),
      output,
    },
    setSecret: { input: object({ entity: { type: "string" }, name: { type: "string" }, value: { type: "string", minLength: 1, maxLength: 65536 } }, ["entity", "name", "value"]), output },
    unsetSecret: { input: object({ entity: { type: "string" }, name: { type: "string" } }, ["entity", "name"]), output },
    dismissRequest: { input: object({ id: { type: "string" } }, ["id"]), output },
    setLocal: { input: object({ id: { type: ["string", "null"] } }, ["id"]), output },
    exportBundle: { input: object({ passphrase: { type: "string" } }, ["passphrase"]), output },
    previewImport: { input: object({ content: { type: "string", maxLength: 67108864 }, passphrase: { type: "string" } }, ["content", "passphrase"]), output },
    applyImport: {
      input: object({
        content: { type: "string", maxLength: 67108864 }, passphrase: { type: "string" },
        mode: { enum: ["merge", "replace"] }, localMachine: { type: ["string", "null"] },
      }, ["content", "passphrase", "mode"]),
      output,
    },
  },
  events: {},
} as const satisfies Rpc.PortableDefinition

export type Effect = "allow" | "ask" | "deny"
export type Status = "set" | "unset"

export interface AgentView { readonly id: string; readonly name: string; readonly mode: string }
export interface MachineView {
  readonly id: string
  readonly label?: string
  readonly os: string
  readonly ssh?: string
  readonly forwardX11: boolean
  readonly forwardAgent: boolean
  readonly local: boolean
  readonly secrets: Record<string, Status>
}
export interface EnvView { readonly name: string; readonly description: string; readonly secret: boolean; readonly status: Status }
export interface RequestView { readonly id: string; readonly entity: string; readonly name: string; readonly label: string; readonly purpose: string; readonly createdAt: string }

/** Everything the GUI shows. Never contains secret values. */
export interface StateView {
  readonly revision: number
  /** Changes whenever anything shown changes; the GUI re-renders only then. */
  readonly fingerprint: string
  readonly machines: readonly MachineView[]
  readonly env: readonly EnvView[]
  readonly agents: readonly AgentView[]
  readonly machineCapabilities: readonly string[]
  readonly envCapabilities: readonly string[]
  readonly defaults: Record<string, Effect>
  /** entity -> agent ('*' = any agent) -> capability -> effect */
  readonly cells: Record<string, Record<string, Record<string, Effect>>>
  /** Root of the given session's tree and its override cells (entity -> capability -> effect). */
  readonly session?: { readonly root: string; readonly cells: Record<string, Record<string, Effect>> }
  readonly requests: readonly RequestView[]
}

export interface ImportPreview {
  readonly plugin: string
  readonly createdAt: string
  readonly machines: readonly { id: string; status: string }[]
  readonly env: readonly { id: string; status: string }[]
  readonly secrets: number
  readonly permissionEntities: number
}

/** Effect shown for a cell: its own value, else what it inherits. */
export function inherited(state: Pick<StateView, "cells" | "defaults">, entity: string, capability: string, agent: string): Effect {
  if (agent !== "*") {
    const own = state.cells[entity]?.[agent]?.[capability]
    if (own) return own
  }
  return state.cells[entity]?.["*"]?.[capability] ?? state.defaults[capability] ?? "ask"
}
