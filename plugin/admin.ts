import { createHash } from "node:crypto"
import { decryptBundle, diffRecords, encryptBundle, type EntityPolicy, type SecretValue } from "oc-secure-kit"
import {
  defaultEffect, ENV_CAPABILITIES, ENV_VALUE, envEntity, isFillableSlot, MACHINE_CAPABILITIES, normalizeEnvVar, normalizeMachine,
  type EnvVar, type Machine,
} from "./model.js"
import type { AgentView, Effect, ImportPreview, RequestView, StateView } from "./rpc.js"
import { PLUGIN_ID, type MachineService } from "./service.js"

export const BUNDLE_VERSION = 1
export interface BundlePayload {
  machines: Record<string, Machine>
  env: Record<string, EnvVar>
  permissions: Record<string, EntityPolicy>
  secrets: SecretValue[]
}

export interface AdminDeps {
  readonly service: MachineService
  /** Agents for the table rows. */
  readonly agents: () => Promise<AgentView[]>
  /** Root of a session tree (the "This session" row covers subagents). */
  readonly root: (sessionID: string) => Promise<string>
  /** Bundle KDF cost; tests lower it. */
  readonly cost?: { N: number; r: number; p: number }
}

const record = (value: unknown, what: string): Record<string, unknown> => {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid ${what}`)
  return value as Record<string, unknown>
}
const string = (value: unknown, what: string): string => {
  if (typeof value !== "string" || !value) throw new Error(`Invalid ${what}`)
  return value
}
const isEnvEntity = (entity: string) => entity.startsWith("env:")

/** Server side of the GUI. Every mutation the agent cannot make (permissions, secrets, export/import) lives here. */
export function createAdmin(deps: AdminDeps) {
  const { service } = deps

  /** Which secret an entity/name pair means, checked against the current configuration. */
  async function secretTarget(entity: string, name: string): Promise<string> {
    if (isEnvEntity(entity)) {
      const variable = await service.store.getEnv(entity.slice(4))
      if (!variable) throw new Error(`No env var ${entity.slice(4)}`)
      if (!variable.secret || name !== ENV_VALUE) throw new Error(`${variable.name} is not a secret variable`)
      return `$${variable.name}`
    }
    const machine = await service.store.get(entity)
    if (!machine) throw new Error(`No machine ${entity}`)
    if (!isFillableSlot(machine, name)) throw new Error(`${machine.id} has no ${name} secret`)
    return `${({ sudo: "sudo password", "ssh-password": "ssh password", "key-passphrase": "key passphrase" } as Record<string, string>)[name] ?? name} for ${machine.id}`
  }

  async function state(input: { sessionID?: string }): Promise<StateView> {
    const [machines, env, local, requests, agents] = await Promise.all([
      service.store.list(), service.store.listEnv(), service.store.localMachine(), service.requests.list(), deps.agents().catch(() => []),
    ])
    const doc = await service.policy.reload()
    const machineViews = await Promise.all(machines.map(async machine => ({
      id: machine.id, ...(machine.label && { label: machine.label }), os: machine.os,
      ...(machine.ssh && { ssh: `${machine.ssh.user ? `${machine.ssh.user}@` : ""}${machine.ssh.host}${machine.ssh.port ? `:${machine.ssh.port}` : ""} · ${machine.ssh.auth}${machine.ssh.proxyJump ? ` · via ${machine.ssh.proxyJump}` : ""}` }),
      forwardX11: !!machine.ssh?.forwardX11, forwardAgent: !!machine.ssh?.forwardAgent,
      local: machine.id === local, secrets: await service.machineSecretStatus(machine),
    })))
    const envViews = await Promise.all(env.map(async variable => ({
      name: variable.name, description: variable.description, secret: variable.secret, status: await service.envStatus(variable),
    })))
    const requestViews: RequestView[] = []
    for (const request of requests) {
      try { requestViews.push({ ...request, label: await secretTarget(request.entity, request.name) }) }
      catch { await service.requests.remove({ id: request.id }) } // the machine or variable is gone
    }
    const cells = Object.fromEntries(Object.entries(doc.entities).map(([entity, policy]) => [entity, policy.agents])) as StateView["cells"]
    let session: StateView["session"]
    if (input.sessionID) {
      const root = await deps.root(input.sessionID)
      session = { root, cells: (doc.sessions[root]?.entities ?? {}) as Record<string, Record<string, Effect>> }
    }
    const defaults = Object.fromEntries([...MACHINE_CAPABILITIES, ...ENV_CAPABILITIES].map(capability => [capability, defaultEffect(capability)]))
    const view = {
      revision: doc.revision, machines: machineViews, env: envViews, agents,
      machineCapabilities: [...MACHINE_CAPABILITIES], envCapabilities: [...ENV_CAPABILITIES], defaults, cells,
      ...(session && { session }), requests: requestViews,
    }
    return { ...view, fingerprint: createHash("sha256").update(JSON.stringify(view)).digest("hex").slice(0, 16) }
  }

  async function setCells(input: { expectedRevision?: number; sessionID?: string; changes: { entity: string; capability: string; effect: Effect | null; agent?: string; session?: boolean }[] }) {
    const [machines, env] = await Promise.all([service.store.list(), service.store.listEnv()])
    const machineIds = new Set(machines.map(machine => machine.id))
    const envIds = new Set(env.map(variable => envEntity(variable.name)))
    let root: string | undefined
    const changes = []
    for (const change of input.changes) {
      const allowed: readonly string[] = isEnvEntity(change.entity) ? ENV_CAPABILITIES : MACHINE_CAPABILITIES
      if (!(isEnvEntity(change.entity) ? envIds : machineIds).has(change.entity)) throw new Error(`Unknown ${change.entity}`)
      if (!allowed.includes(change.capability)) throw new Error(`Unknown permission ${change.capability}`)
      if (change.session) {
        if (!input.sessionID) throw new Error("A session is needed for the This session row")
        root ??= await deps.root(input.sessionID)
        changes.push({ entity: change.entity, capability: change.capability, effect: change.effect, row: { session: root } })
      } else {
        changes.push({ entity: change.entity, capability: change.capability, effect: change.effect, row: { agent: string(change.agent, "agent") } })
      }
    }
    await service.policy.setCells(changes, input.expectedRevision)
    return state({ ...(input.sessionID && { sessionID: input.sessionID }) })
  }

  async function setSecret(input: { entity: string; name: string; value: string }) {
    const label = await secretTarget(input.entity, input.name)
    await service.vault.set(input.entity, input.name, input.value)
    await service.requests.remove({ entity: input.entity, name: input.name })
    await service.syncRedactor()
    return { stored: label, short: input.value.length < 6 }
  }

  async function unsetSecret(input: { entity: string; name: string }) {
    const label = await secretTarget(input.entity, input.name)
    return { removed: await service.vault.delete(input.entity, input.name), secret: label }
  }

  async function setLocal(input: { id: string | null }) {
    await service.store.setLocal(input.id ?? undefined)
    return { local: input.id }
  }

  async function exportBundle(input: { passphrase: string }) {
    const { machines, env } = await service.store.exportAll()
    const entities = [...Object.keys(machines), ...Object.keys(env).map(envEntity)]
    const payload: BundlePayload = {
      machines, env,
      permissions: await service.policy.exportEntities(entities),
      secrets: (await service.vault.values()).filter(item => entities.includes(item.entity)),
    }
    const content = await encryptBundle({ plugin: PLUGIN_ID, schemaVersion: BUNDLE_VERSION, payload }, input.passphrase, deps.cost ? { cost: deps.cost } : {})
    return {
      name: `oc-machine-${new Date().toISOString().slice(0, 10)}.ocbundle`, content,
      counts: { machines: Object.keys(machines).length, env: Object.keys(env).length, secrets: payload.secrets.length },
    }
  }

  async function open(content: string, passphrase: string): Promise<{ payload: BundlePayload; createdAt: string }> {
    const { payload: raw, header } = await decryptBundle<unknown>(content, passphrase, { plugin: PLUGIN_ID, currentVersion: BUNDLE_VERSION })
    const data = record(raw, "bundle contents")
    const machines = Object.fromEntries(Object.values(record(data.machines ?? {}, "machines")).map(item => {
      const machine = normalizeMachine(item, new Date((item as Machine).updatedAt ?? Date.now()))
      return [machine.id, machine]
    }))
    const env = Object.fromEntries(Object.values(record(data.env ?? {}, "env")).map(item => {
      const variable = normalizeEnvVar(item, new Date((item as EnvVar).updatedAt ?? Date.now()))
      return [variable.name, variable]
    }))
    const entities = new Set([...Object.keys(machines), ...Object.keys(env).map(envEntity)])
    const permissions = record(data.permissions ?? {}, "permissions") as Record<string, EntityPolicy>
    for (const entity of Object.keys(permissions)) if (!entities.has(entity)) throw new Error(`Bundle has permissions for unknown ${entity}`)
    if (!Array.isArray(data.secrets)) throw new Error("Invalid secrets")
    const secrets = (data.secrets as SecretValue[]).map(item => {
      const entity = string(item?.entity, "secret"), name = string(item?.name, "secret"), value = string(item?.value, "secret")
      if (isEnvEntity(entity)) {
        if (!env[entity.slice(4)]?.secret || name !== ENV_VALUE) throw new Error(`Bundle has an unexpected secret for ${entity}`)
      } else {
        const machine = machines[entity]
        if (!machine || !(isFillableSlot(machine, name) || (name === "ssh-key" && machine.ssh?.auth === "generated"))) throw new Error(`Bundle has an unexpected secret for ${entity}`)
      }
      return { entity, name, value }
    })
    return { payload: { machines, env, permissions, secrets }, createdAt: header.createdAt }
  }

  async function previewImport(input: { content: string; passphrase: string }): Promise<ImportPreview> {
    const { payload, createdAt } = await open(input.content, input.passphrase)
    const current = await service.store.exportAll()
    const strip = <T extends { updatedAt?: string }>(items: Record<string, T>) =>
      Object.fromEntries(Object.entries(items).map(([id, { updatedAt: _, ...rest }]) => [id, rest]))
    return {
      plugin: PLUGIN_ID, createdAt,
      machines: diffRecords(strip(current.machines), strip(payload.machines)),
      env: diffRecords(strip(current.env), strip(payload.env)),
      secrets: payload.secrets.length, permissionEntities: Object.keys(payload.permissions).length,
    }
  }

  async function applyImport(input: { content: string; passphrase: string; mode: "merge" | "replace"; localMachine?: string | null }) {
    const { payload } = await open(input.content, input.passphrase)
    if (input.localMachine && !payload.machines[input.localMachine] && (input.mode === "replace" || !await service.store.get(input.localMachine))) {
      throw new Error(`No machine ${input.localMachine} to mark as this computer`)
    }
    const imported = [...Object.keys(payload.machines), ...Object.keys(payload.env).map(envEntity)]
    if (input.mode === "replace") {
      const current = await service.store.exportAll()
      for (const entity of [...Object.keys(current.machines), ...Object.keys(current.env).map(envEntity)]) {
        await service.vault.deleteEntity(entity)
        await service.policy.removeEntity(entity)
      }
    }
    await service.store.importAll({ machines: payload.machines, env: payload.env }, input.mode === "replace")
    // Merge keeps local secrets and permissions for an item unless the bundle brings its own.
    await service.vault.importValues(payload.secrets, [...new Set(payload.secrets.map(item => item.entity))])
    await service.policy.importEntities(payload.permissions)
    for (const machine of Object.values(payload.machines)) {
      const saved = await service.store.get(machine.id)
      if (saved) await service.pruneMachineSecrets(saved)
    }
    for (const variable of Object.values(payload.env)) if (!variable.secret) await service.vault.deleteEntity(envEntity(variable.name))
    for (const request of await service.requests.list()) {
      if (await service.vault.has(request.entity, request.name)) await service.requests.remove({ id: request.id })
    }
    if (input.localMachine !== undefined) await service.store.setLocal(input.localMachine ?? undefined)
    await service.refreshRedactor()
    return { imported: { machines: Object.keys(payload.machines).length, env: Object.keys(payload.env).length, secrets: payload.secrets.length }, mode: input.mode }
  }

  return {
    state, setCells, setSecret, unsetSecret, setLocal, exportBundle, previewImport, applyImport,
    dismissRequest: async (input: { id: string }) => ({ dismissed: await service.requests.remove({ id: input.id }) }),
  }
}
export type Admin = ReturnType<typeof createAdmin>
