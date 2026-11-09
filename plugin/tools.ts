import type { ToolContext } from "@opencode/plugin/promise/tool"
import type { PermissionBridge } from "oc-secure-kit"
import { capabilities, isFillableSlot, mergeMachine, normalizeMachine, secretSlots, type Machine } from "./model.js"
import type { MachineService } from "./service.js"
import { renderHost, validateConfig } from "./sshconfig.js"

export const TOOL_NAMES = ["machine_list", "machine_get", "machine_upsert", "machine_remove", "machine_request_secret", "machine_ssh_config"] as const

export interface ToolDefinition {
  readonly name: (typeof TOOL_NAMES)[number]
  readonly description: string
  readonly input: Record<string, unknown>
  readonly execute: (input: any, context: ToolContext) => Promise<{ content: string; metadata?: Record<string, unknown> }>
}

const ID = { type: "string", minLength: 1, maxLength: 64, pattern: "^[A-Za-z0-9][A-Za-z0-9._-]*$", description: "Machine ID; also the ssh Host alias" }
const SSH_HINT = 'Connect from the shell with: ssh -F "$OCM_SSH_CONFIG" <machine-id>'

const SSH_SCHEMA = {
  type: "object",
  description: "SSH settings. Omit for machines you never connect to. In upsert, fields merge into the existing ssh settings and null clears a field.",
  properties: {
    host: { type: "string", description: "Hostname or IP" },
    user: { type: "string" },
    port: { type: "integer", minimum: 1, maximum: 65535 },
    proxyJump: { type: "string", description: "Another machine ID or [user@]host[:port]; comma-separated for chains" },
    auth: { type: "string", enum: ["agent", "key", "password", "generated"], description: "agent: ssh-agent / 1Password / Secretive; key: a key file; password: user enters it as a secret; generated: per-machine key (key generation comes later)" },
    identityFile: { type: "string", description: "Private key path for auth=key (~ allowed)" },
    identityAgent: { type: "string", description: "Agent socket path for auth=agent, if not $SSH_AUTH_SOCK" },
    forwardX11: { type: "boolean" },
    forwardX11Trusted: { type: "boolean" },
    forwardAgent: { type: "boolean" },
    localForwards: { type: "array", items: { type: "string" }, description: "e.g. 8080:localhost:80 or 127.0.0.1:5432:db:5432" },
    remoteForwards: { type: "array", items: { type: "string" } },
    serverAliveInterval: { type: "integer", minimum: 0, maximum: 3600 },
    options: { type: "object", additionalProperties: { type: "string" }, description: "Other ssh_config options, e.g. {\"Compression\":\"yes\"}" },
  },
} as const

const ENV_SCHEMA = {
  type: "array",
  description: "Replaces the whole env list when given. Secret variables never take a value here: ask the user with machine_request_secret.",
  items: {
    type: "object",
    properties: {
      name: { type: "string" },
      secret: { type: "boolean", description: "Value is stored encrypted and entered by the user" },
      value: { type: "string", description: "Only for non-secret variables" },
      override: { type: "boolean", description: "Replace a variable the shell already has (default false)" },
    },
    required: ["name"],
    additionalProperties: false,
  },
} as const

function json(value: unknown, metadata?: Record<string, unknown>) {
  return { content: JSON.stringify(value, null, 2), ...(metadata && { metadata }) }
}

export function createTools(service: MachineService, bridge: PermissionBridge): ToolDefinition[] {
  const check = (context: ToolContext, capability: string, machine: string, metadata?: Record<string, unknown>) =>
    bridge.check({
      sessionID: context.sessionID, agent: context.agent, capability, entities: [machine],
      source: { type: "tool", messageID: context.messageID, id: context.id },
      ...(metadata && { metadata }),
    })

  const summary = async (machine: Machine, local: string | undefined) => ({
    id: machine.id,
    ...(machine.label && { label: machine.label }),
    os: machine.os,
    local: machine.id === local,
    ...(machine.ssh && { ssh: `${machine.ssh.user ? `${machine.ssh.user}@` : ""}${machine.ssh.host}${machine.ssh.port ? `:${machine.ssh.port}` : ""} (${machine.ssh.auth})` }),
    env: machine.env.map(variable => variable.name),
    secrets: await service.secretStatus(machine),
  })

  const require = async (id: string) => {
    const machine = await service.store.get(id)
    if (!machine) throw new Error(`No machine ${JSON.stringify(id)}. Use machine_list to see machines.`)
    return machine
  }

  return [
    {
      name: "machine_list",
      description: "List configured machines (this host and remote ones): connection summary, env var names, and which secrets are set. Secret values are never shown. " + SSH_HINT,
      input: { type: "object", properties: {}, additionalProperties: false },
      execute: async () => {
        const local = await service.store.localMachine()
        const machines = await Promise.all((await service.store.list()).map(machine => summary(machine, local)))
        return json({ machines, sshConfig: service.sshConfigPath, usage: SSH_HINT })
      },
    },
    {
      name: "machine_get",
      description: "Full configuration of one machine, which secrets are set, and what this agent may do on it (allow/ask/deny per capability). Secret values are never shown.",
      input: { type: "object", properties: { id: ID }, required: ["id"], additionalProperties: false },
      execute: async (input: { id: string }, context) => {
        const machine = await require(input.id)
        const local = await service.store.localMachine()
        const permissions = Object.fromEntries(await Promise.all(capabilities(machine).map(async capability =>
          [capability, (await bridge.effect({ sessionID: context.sessionID, agent: context.agent, capability, entity: machine.id })).effect] as const)))
        const shell = await service.shellPolicy(machine.id)
        return json({
          machine, local: machine.id === local, secrets: await service.secretStatus(machine), permissions,
          ...(machine.ssh && { ssh: shell.ssh ? `ssh -F "$OCM_SSH_CONFIG" ${machine.id}` : "ssh is not allowed for the agent shell on this machine" }),
          note: "Permissions are changed by the user in the Machines table, not by tools.",
        })
      },
    },
    {
      name: "machine_upsert",
      description: "Create or update a machine's non-secret configuration (ssh settings, env vars, notes). Fields merge into the existing machine; null clears a field; env replaces the list. Set local=true for the machine OpenCode runs on: its allowed env vars are added to new shells. Secrets (sudo/ssh passwords, key passphrases, secret env values) are never passed here; use machine_request_secret.",
      input: {
        type: "object",
        properties: {
          id: ID,
          rename: { ...ID, description: "New ID for an existing machine" },
          label: { type: ["string", "null"] },
          os: { type: "string", enum: ["linux", "macos"] },
          local: { type: "boolean", description: "This is the host OpenCode runs on" },
          ssh: { anyOf: [SSH_SCHEMA, { type: "null" }] },
          env: ENV_SCHEMA,
          notes: { type: ["string", "null"] },
        },
        required: ["id"],
        additionalProperties: false,
      },
      execute: async (input: Record<string, unknown> & { id: string; rename?: string; local?: boolean }, context) => {
        const { id, rename, local, ...patch } = input
        const existing = await service.store.get(id)
        await check(context, "manage", id, { operation: existing ? "update" : "create" })
        if (rename !== undefined && !existing) throw new Error(`Cannot rename: no machine ${id}`)
        if (rename !== undefined && rename !== id) await check(context, "manage", rename, { operation: "rename", from: id })
        const target = rename ?? id
        const candidate = normalizeMachine({ ...mergeMachine(existing, patch), id: target, ...(!existing && !("os" in patch) && { os: "linux" }) })
        if (candidate.ssh) {
          const others = new Map((await service.store.list()).filter(machine => machine.id !== id).map(machine => [machine.id, machine] as const))
          others.set(candidate.id, candidate)
          const block = renderHost(candidate, others, { keysDir: service.keysDir, policy: () => ({ ssh: true, x11: true, agentForward: true }) })
          await validateConfig(block ?? "", [candidate.id])
        }
        const saved = await service.store.put(candidate, existing && target !== id ? id : undefined)
        if (existing && target !== id) {
          await service.vault.renameEntity(id, target)
          await service.policy.renameEntity(id, target)
          await service.requests.remove({ entity: id })
        }
        await service.pruneOrphans(saved)
        if (local === true) await service.store.setLocal(saved.id)
        if (local === false && (await service.store.localMachine()) === saved.id) await service.store.setLocal(undefined)
        await service.writeSshConfig()
        const secrets = await service.secretStatus(saved)
        const missing = Object.entries(secrets).filter(([slot, state]) => state === "unset" && slot !== "sudo" && slot !== "ssh-key").map(([slot]) => slot)
        return json({
          saved, local: (await service.store.localMachine()) === saved.id, secrets,
          ...(missing.length && { next: `Ask the user for: ${missing.join(", ")} (machine_request_secret).` }),
          ...(saved.ssh && { usage: `ssh -F "$OCM_SSH_CONFIG" ${saved.id}` }),
        })
      },
    },
    {
      name: "machine_remove",
      description: "Delete a machine, its stored secrets and its permission settings. Asks the user by default.",
      input: { type: "object", properties: { id: ID }, required: ["id"], additionalProperties: false },
      execute: async (input: { id: string }, context) => {
        const machine = await require(input.id)
        await check(context, "remove", machine.id, { secrets: (await service.vault.list(machine.id)).length })
        await service.store.remove(machine.id)
        await service.vault.deleteEntity(machine.id)
        await service.policy.removeEntity(machine.id)
        await service.requests.remove({ entity: machine.id })
        await service.writeSshConfig()
        return json({ removed: machine.id })
      },
    },
    {
      name: "machine_request_secret",
      description: "Ask the user to enter a secret for a machine: 'sudo', 'ssh-password', 'key-passphrase' or 'env:<NAME>' for a secret env var. The user types it outside the chat; you only ever see whether it is set.",
      input: {
        type: "object",
        properties: {
          id: ID,
          slot: { type: "string", description: "sudo | ssh-password | key-passphrase | env:<NAME>" },
          purpose: { type: "string", maxLength: 300, description: "Why it is needed, shown to the user" },
        },
        required: ["id", "slot"],
        additionalProperties: false,
      },
      execute: async (input: { id: string; slot: string; purpose?: string }, context) => {
        const machine = await require(input.id)
        if (!isFillableSlot(machine, input.slot)) {
          throw new Error(`${input.slot} is not a secret of ${machine.id}. Its secrets are: ${secretSlots(machine).filter(slot => slot !== "ssh-key").join(", ")}`)
        }
        const request = await service.requests.add({ entity: machine.id, name: input.slot, purpose: input.purpose ?? "", sessionID: context.sessionID })
        const already = await service.vault.has(machine.id, input.slot)
        return json({
          requested: { machine: machine.id, slot: input.slot, id: request.id },
          status: already ? "set (the user may replace it)" : "unset",
          tellUser: `Please enter the ${input.slot} secret for ${machine.id} in Settings > Machines, or run: pixi run secret-set ${machine.id} ${input.slot}  (in the oc-machine folder)`,
        })
      },
    },
    {
      name: "machine_ssh_config",
      description: "Show the generated ssh_config (no secrets) for one machine or all of them, and its path. Use it to debug connections; the file is already used via OCM_SSH_CONFIG.",
      input: { type: "object", properties: { id: ID }, additionalProperties: false },
      execute: async (input: { id?: string }) => {
        const text = await service.writeSshConfig()
        if (!input.id) return json({ path: service.sshConfigPath, config: text, usage: SSH_HINT })
        await require(input.id)
        const block = text.split("\n\n").find(part => part.split("\n").includes(`Host ${input.id}`) || part.startsWith(`# ${input.id} skipped`))
        return json({ path: service.sshConfigPath, config: block ?? `${input.id} has no ssh settings, or ssh is not allowed for the agent shell`, usage: SSH_HINT })
      },
    },
  ]
}
