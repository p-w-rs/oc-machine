import { validName } from "oc-secure-kit"

export const MACHINES_FORMAT = "oc-machines/1"

export type Os = "linux" | "macos"
export type SshAuth = "agent" | "key" | "password" | "generated"

export interface EnvVar {
  readonly name: string
  /** Secret values live in the vault as `env:<name>`; non-secret values live here. */
  readonly secret: boolean
  readonly value?: string
  /** Replace a variable the shell already has. Off by default, so existing environments behave as before. */
  readonly override?: boolean
}

export interface SshConfig {
  readonly host: string
  readonly user?: string
  readonly port?: number
  /** Another machine's ID, or a raw `[user@]host[:port]` jump spec (comma-separated for chains). */
  readonly proxyJump?: string
  readonly auth: SshAuth
  /** For `key` auth. `~` is allowed. */
  readonly identityFile?: string
  /** Custom agent socket (1Password, Secretive, ...). For `agent` auth; default is `$SSH_AUTH_SOCK`. */
  readonly identityAgent?: string
  readonly forwardX11?: boolean
  readonly forwardX11Trusted?: boolean
  readonly forwardAgent?: boolean
  /** `[bind:]port:host:hostport` */
  readonly localForwards?: readonly string[]
  readonly remoteForwards?: readonly string[]
  readonly serverAliveInterval?: number
  /** Any other ssh_config options, e.g. `{ "Compression": "yes" }`. */
  readonly options?: Readonly<Record<string, string>>
}

export interface Machine {
  readonly id: string
  readonly label?: string
  readonly os: Os
  readonly ssh?: SshConfig
  readonly env: readonly EnvVar[]
  readonly notes?: string
  readonly updatedAt: string
}

/** Secret slots a machine may have. `env:<NAME>` slots exist for each secret env var. */
export type SecretSlot = "sudo" | "ssh-password" | "key-passphrase" | "ssh-key" | `env:${string}`

export const BASE_CAPABILITIES = ["ssh", "sudo", "x11", "agent-forward", "manage", "remove"] as const
export type Capability = (typeof BASE_CAPABILITIES)[number] | `env.${string}`

/** Usability first: unset cells allow, except sudo and removal, which ask. */
export function defaultEffect(capability: string): "allow" | "ask" {
  return capability === "sudo" || capability === "remove" ? "ask" : "allow"
}

export function capabilities(machine: Machine): Capability[] {
  return [...BASE_CAPABILITIES, ...machine.env.map(variable => `env.${variable.name}` as const)]
}

export function secretSlots(machine: Machine): SecretSlot[] {
  const slots: SecretSlot[] = ["sudo"]
  if (machine.ssh?.auth === "password") slots.push("ssh-password")
  if (machine.ssh?.auth === "key") slots.push("key-passphrase")
  if (machine.ssh?.auth === "generated") slots.push("ssh-key")
  for (const variable of machine.env) if (variable.secret) slots.push(`env:${variable.name}`)
  return slots
}

/** Slots the user may fill. `ssh-key` is created by key generation, never typed in. */
export function isFillableSlot(machine: Machine, slot: string): slot is SecretSlot {
  return slot !== "ssh-key" && (secretSlots(machine) as string[]).includes(slot)
}

const HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?|\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9A-Fa-f:]+(?:%[\w.]+)?\]?)$/
const USER = /^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$/
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/
const JUMP = /^(?:[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}@)?[A-Za-z0-9.:\[\]%_-]+(?::\d{1,5})?$/
const FORWARD = /^(?:(?:\[[^\]\s]+\]|[A-Za-z0-9.*_-]+):)?\d{1,5}[: ](?:\[[^\]\s]+\]|[A-Za-z0-9._-]+):\d{1,5}$|^\/[^\s]+ \/[^\s]+$/
const OPTION_NAME = /^[A-Za-z][A-Za-z0-9]{1,63}$/
/** Options that would change the structure of the generated file. */
const STRUCTURAL = new Set(["host", "match", "include"])
const MANAGED = new Set(["hostname", "user", "port", "proxyjump", "identityfile", "identityagent", "identitiesonly", "forwardx11",
  "forwardx11trusted", "forwardagent", "localforward", "remoteforward", "serveraliveinterval", "preferredauthentications", "passwordauthentication"])
const CONTROL = /[\u0000-\u001f\u007f]/

const fail = (message: string): never => { throw new Error(message) }
const text = (value: unknown, field: string, max: number): string | undefined => {
  if (value === undefined || value === null || value === "") return undefined
  if (typeof value !== "string" || value.length > max || CONTROL.test(value)) fail(`${field} must be a single-line string up to ${max} characters`)
  return value as string
}
const flag = (value: unknown, field: string): boolean | undefined => {
  if (value === undefined || value === null) return undefined
  if (typeof value !== "boolean") fail(`${field} must be true or false`)
  return value as boolean
}
const port = (value: unknown, field: string): number | undefined => {
  if (value === undefined || value === null) return undefined
  if (!Number.isInteger(value) || (value as number) < 1 || (value as number) > 65535) fail(`${field} must be a port number 1-65535`)
  return value as number
}

export function normalizeSsh(input: unknown, machineId: string): SshConfig {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("ssh must be an object")
  const raw = input as Record<string, unknown>
  const known = new Set(["host", "user", "port", "proxyJump", "auth", "identityFile", "identityAgent", "forwardX11", "forwardX11Trusted",
    "forwardAgent", "localForwards", "remoteForwards", "serverAliveInterval", "options"])
  for (const key of Object.keys(raw)) if (!known.has(key)) fail(`Unknown ssh field ${JSON.stringify(key)}`)
  const host = text(raw.host, "ssh.host", 253) ?? fail("ssh.host is required")
  if (!HOST.test(host)) fail(`ssh.host ${JSON.stringify(host)} is not a hostname or IP address`)
  const user = text(raw.user, "ssh.user", 64)
  if (user !== undefined && !USER.test(user)) fail(`ssh.user ${JSON.stringify(user)} is not a valid user name`)
  const auth = (raw.auth ?? "agent") as SshAuth
  if (!["agent", "key", "password", "generated"].includes(auth)) fail("ssh.auth must be agent, key, password or generated")
  const identityFile = text(raw.identityFile, "ssh.identityFile", 1024)
  if (auth === "key" && !identityFile) fail("ssh.identityFile is required for key auth")
  if (identityFile !== undefined && auth !== "key") fail("ssh.identityFile only applies to key auth")
  const identityAgent = text(raw.identityAgent, "ssh.identityAgent", 1024)
  if (identityAgent !== undefined && auth !== "agent") fail("ssh.identityAgent only applies to agent auth")
  const proxyJump = text(raw.proxyJump, "ssh.proxyJump", 1024)
  if (proxyJump !== undefined) {
    for (const hop of proxyJump.split(",")) if (!JUMP.test(hop)) fail(`ssh.proxyJump hop ${JSON.stringify(hop)} is not [user@]host[:port] or a machine ID`)
    if (proxyJump.split(",").includes(machineId)) fail("ssh.proxyJump cannot point at the machine itself")
  }
  const forwards = (value: unknown, field: string): string[] | undefined => {
    if (value === undefined || value === null) return undefined
    if (!Array.isArray(value) || value.length > 32) fail(`${field} must be a list of up to 32 forwards`)
    return (value as unknown[]).map(item => {
      const forward = text(item, field, 300) ?? fail(`${field} entries must be non-empty`)
      if (!FORWARD.test(forward)) fail(`${field} entry ${JSON.stringify(forward)} must look like [bind:]port:host:hostport`)
      return forward.replace(/^(.*\d) (.*)$/, "$1:$2")
    })
  }
  const interval = raw.serverAliveInterval
  if (interval !== undefined && interval !== null && (!Number.isInteger(interval) || (interval as number) < 0 || (interval as number) > 3600)) {
    fail("ssh.serverAliveInterval must be 0-3600 seconds")
  }
  let options: Record<string, string> | undefined
  if (raw.options !== undefined && raw.options !== null) {
    if (typeof raw.options !== "object" || Array.isArray(raw.options)) fail("ssh.options must be an object of option -> value")
    options = {}
    for (const [name, value] of Object.entries(raw.options as Record<string, unknown>)) {
      if (!OPTION_NAME.test(name)) fail(`ssh.options key ${JSON.stringify(name)} is not an ssh_config option name`)
      const lower = name.toLowerCase()
      if (STRUCTURAL.has(lower)) fail(`ssh.options cannot set ${name}`)
      if (MANAGED.has(lower)) fail(`Set ${name} with its dedicated ssh field, not ssh.options`)
      options[name] = text(value, `ssh.options.${name}`, 1024) ?? fail(`ssh.options.${name} needs a value`)
    }
    if (Object.keys(options).length > 64) fail("ssh.options has too many entries")
  }
  const ssh: SshConfig = {
    host, auth,
    ...(user !== undefined && { user }),
    ...(raw.port !== undefined && raw.port !== null && { port: port(raw.port, "ssh.port") }),
    ...(proxyJump !== undefined && { proxyJump }),
    ...(identityFile !== undefined && { identityFile }),
    ...(identityAgent !== undefined && { identityAgent }),
    ...(flag(raw.forwardX11, "ssh.forwardX11") !== undefined && { forwardX11: raw.forwardX11 as boolean }),
    ...(flag(raw.forwardX11Trusted, "ssh.forwardX11Trusted") !== undefined && { forwardX11Trusted: raw.forwardX11Trusted as boolean }),
    ...(flag(raw.forwardAgent, "ssh.forwardAgent") !== undefined && { forwardAgent: raw.forwardAgent as boolean }),
    ...(forwards(raw.localForwards, "ssh.localForwards")?.length && { localForwards: forwards(raw.localForwards, "ssh.localForwards") }),
    ...(forwards(raw.remoteForwards, "ssh.remoteForwards")?.length && { remoteForwards: forwards(raw.remoteForwards, "ssh.remoteForwards") }),
    ...(interval !== undefined && interval !== null && { serverAliveInterval: interval as number }),
    ...(options && Object.keys(options).length && { options }),
  }
  return ssh
}

export function normalizeEnv(input: unknown): EnvVar[] {
  if (input === undefined || input === null) return []
  if (!Array.isArray(input) || input.length > 200) return fail("env must be a list of up to 200 variables")
  const seen = new Set<string>()
  return input.map((item: unknown) => {
    if (!item || typeof item !== "object") return fail("env entries must be objects")
    const raw = item as Record<string, unknown>
    for (const key of Object.keys(raw)) if (!["name", "secret", "value", "override"].includes(key)) fail(`Unknown env field ${JSON.stringify(key)}`)
    const name = typeof raw.name === "string" && ENV_NAME.test(raw.name) ? raw.name : fail(`env name ${JSON.stringify(raw.name)} is not a valid variable name`)
    if (seen.has(name)) fail(`env ${name} is listed twice`)
    seen.add(name)
    const secret = flag(raw.secret, `env.${name}.secret`) ?? false
    if (secret && raw.value !== undefined && raw.value !== null) {
      fail(`env ${name} is secret: do not pass its value. Ask the user to enter it with machine_request_secret.`)
    }
    if (!secret && (raw.value === undefined || raw.value === null)) fail(`env ${name} needs a value (or set secret: true)`)
    if (!secret && (typeof raw.value !== "string" || raw.value.length > 32 * 1024 || raw.value.includes("\0"))) fail(`env ${name} value must be a string up to 32 KiB`)
    const override = flag(raw.override, `env.${name}.override`)
    return { name, secret, ...(!secret && { value: raw.value as string }), ...(override && { override: true }) }
  })
}

/** Validates a complete machine. Unknown fields are rejected so typos surface instead of being ignored. */
export function normalizeMachine(input: unknown, now = new Date()): Machine {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("machine must be an object")
  const raw = input as Record<string, unknown>
  for (const key of Object.keys(raw)) if (!["id", "label", "os", "ssh", "env", "notes", "updatedAt"].includes(key)) fail(`Unknown machine field ${JSON.stringify(key)}`)
  const id = validName("machine", raw.id as string)
  if (id.length > 64 || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(id)) fail("machine id must be 1-64 letters, digits, '.', '_' or '-' (it is also the ssh Host alias)")
  const os = (raw.os ?? "linux") as Os
  if (os !== "linux" && os !== "macos") fail("os must be linux or macos")
  const label = text(raw.label, "label", 120)
  const notes = typeof raw.notes === "string" && raw.notes.length <= 4000 ? raw.notes : raw.notes === undefined || raw.notes === null ? undefined : fail("notes must be text up to 4000 characters")
  return {
    id, os,
    ...(label !== undefined && { label }),
    ...(raw.ssh !== undefined && raw.ssh !== null && { ssh: normalizeSsh(raw.ssh, id) }),
    env: normalizeEnv(raw.env),
    ...(notes && { notes }),
    updatedAt: now.toISOString(),
  }
}

/**
 * Merges an agent's partial update into an existing machine: top-level and `ssh` fields are merged, `null` clears a
 * field, and `env` (when given) replaces the list.
 */
export function mergeMachine(existing: Machine | undefined, patch: Record<string, unknown>): Record<string, unknown> {
  const base: Record<string, unknown> = existing ? structuredClone(existing) as unknown as Record<string, unknown> : {}
  delete base.updatedAt
  for (const [key, value] of Object.entries(patch)) {
    if (key === "ssh" && value && typeof value === "object" && !Array.isArray(value) && base.ssh) {
      const ssh = { ...(base.ssh as Record<string, unknown>) }
      for (const [field, fieldValue] of Object.entries(value)) {
        if (fieldValue === null) delete ssh[field]
        else ssh[field] = fieldValue
      }
      // Switching auth drops fields that only apply to the old method.
      if ("auth" in value) {
        if (ssh.auth !== "key" && !("identityFile" in value)) delete ssh.identityFile
        if (ssh.auth !== "agent" && !("identityAgent" in value)) delete ssh.identityAgent
      }
      base.ssh = ssh
    } else if (value === null) delete base[key]
    else base[key] = value
  }
  return base
}
