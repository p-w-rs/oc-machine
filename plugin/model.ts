import { validName } from "oc-secure-kit"

export const MACHINES_FORMAT = "oc-machines/1"

export type Os = "linux" | "macos"
export type SshAuth = "agent" | "key" | "password" | "generated"

/** A global env var, usable in shell commands on this computer or any machine. */
export interface EnvVar {
  readonly name: string
  /** What it is for, shown to the agent. Names alone are often cryptic. */
  readonly description: string
  /** Secret values live in the vault; non-secret values live here. */
  readonly secret: boolean
  readonly value?: string
  readonly updatedAt: string
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
  /**
   * Preferred routes, tried in order before `host`/`port`: each is used when its address answers within a second
   * (and, with `network`, only while this computer has an address in that CIDR range, e.g. a home LAN). All routes
   * reach the same machine, so they share one known-hosts entry.
   */
  readonly routes?: readonly SshRoute[]
  /** Where the machine can be reached from, e.g. "office network or work VPN". Shown when it cannot be reached. */
  readonly reachability?: string
}

export interface SshRoute {
  readonly host: string
  readonly port?: number
  /** CIDR, e.g. 192.168.0.0/24: only try this route while on that network. */
  readonly network?: string
}

export interface Machine {
  readonly id: string
  readonly label?: string
  readonly os: Os
  readonly ssh?: SshConfig
  /** Public half of a generated key (auth `generated`); the private key is in the vault. */
  readonly publicKey?: string
  readonly notes?: string
  readonly updatedAt: string
}

/** Secret slots of a machine. */
export type MachineSlot = "sudo" | "ssh-password" | "key-passphrase" | "ssh-key"

/** Machine capabilities in the permission table. */
export const MACHINE_CAPABILITIES = ["ssh", "sudo", "x11", "agent-forward", "manage", "remove"] as const
/** Env var capabilities: each variable is its own entity `env:<NAME>`. */
export const ENV_CAPABILITIES = ["use", "manage", "remove"] as const
/** Vault secret name for an env var's value (entity `env:<NAME>`). */
export const ENV_VALUE = "value"

/** Policy and vault entity of an env var. Machine IDs cannot contain ':', so these never collide. */
export const envEntity = (name: string) => `env:${name}`

/** Usability first: unset cells allow, except sudo and removal, which ask. */
export function defaultEffect(capability: string): "allow" | "ask" {
  return capability === "sudo" || capability === "remove" ? "ask" : "allow"
}

export function machineSlots(machine: Machine): MachineSlot[] {
  const slots: MachineSlot[] = ["sudo"]
  if (machine.ssh?.auth === "password") slots.push("ssh-password")
  if (machine.ssh?.auth === "key") slots.push("key-passphrase")
  if (machine.ssh?.auth === "generated") slots.push("ssh-key")
  return slots
}

/** Slots the user may type in. `ssh-key` is created by key generation; `key-passphrase` is optional. */
export function isFillableSlot(machine: Machine, slot: string): slot is MachineSlot {
  return slot !== "ssh-key" && (machineSlots(machine) as string[]).includes(slot)
}

const HOST = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?|\d{1,3}(?:\.\d{1,3}){3}|\[?[0-9A-Fa-f:]+(?:%[\w.]+)?\]?)$/
const USER = /^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$/
export const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/
const MACHINE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/
const JUMP = /^(?:[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}@)?[A-Za-z0-9.:\[\]%_-]+(?::\d{1,5})?$/
const FORWARD = /^(?:(?:\[[^\]\s]+\]|[A-Za-z0-9.*_-]+):)?\d{1,5}[: ](?:\[[^\]\s]+\]|[A-Za-z0-9._-]+):\d{1,5}$|^\/[^\s]+ \/[^\s]+$/
const CIDR = /^(?:\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}|[0-9A-Fa-f:]+\/\d{1,3})$/
const OPTION_NAME = /^[A-Za-z][A-Za-z0-9]{1,63}$/
const PUBLIC_KEY = /^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [^\r\n']{0,200})?$/
/** Names reserved for the plugin's own shell references. */
export const RESERVED_ENV = /^OCM_|^SSH_ASKPASS|^SUDO_ASKPASS$/
/** Options that would change the structure of the generated file. */
const STRUCTURAL = new Set(["host", "match", "include"])
const MANAGED = new Set(["hostname", "user", "port", "proxyjump", "identityfile", "identityagent", "identitiesonly", "forwardx11",
  "forwardx11trusted", "forwardagent", "localforward", "remoteforward", "serveraliveinterval", "preferredauthentications", "passwordauthentication",
  "pubkeyauthentication"])
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

export function validMachineId(id: unknown): string {
  if (typeof id !== "string" || !MACHINE_ID.test(id)) return fail(`machine id ${JSON.stringify(id)} must be 1-64 letters, digits, '.', '_' or '-' starting with a letter or digit (it is also the ssh Host alias)`)
  return validName("machine", id)
}

export function validEnvName(name: unknown): string {
  if (typeof name !== "string" || !ENV_NAME.test(name)) return fail(`env name ${JSON.stringify(name)} is not a valid variable name`)
  if (RESERVED_ENV.test(name)) fail(`${name} is reserved by oc-machine`)
  return name
}

export function normalizeSsh(input: unknown, machineId: string): SshConfig {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("ssh must be an object")
  const raw = input as Record<string, unknown>
  const known = new Set(["host", "user", "port", "proxyJump", "auth", "identityFile", "identityAgent", "forwardX11", "forwardX11Trusted",
    "forwardAgent", "localForwards", "remoteForwards", "serverAliveInterval", "options", "routes", "reachability"])
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
  if (identityFile?.includes("'")) fail("ssh.identityFile cannot contain a single quote")
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
  const localForwards = forwards(raw.localForwards, "ssh.localForwards")
  const remoteForwards = forwards(raw.remoteForwards, "ssh.remoteForwards")
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
  let routes: SshRoute[] | undefined
  if (raw.routes !== undefined && raw.routes !== null) {
    if (!Array.isArray(raw.routes) || raw.routes.length > 8) fail("ssh.routes must be a list of up to 8 routes")
    routes = (raw.routes as unknown[]).map((item, index) => {
      const field = `ssh.routes[${index}]`
      if (!item || typeof item !== "object" || Array.isArray(item)) fail(`${field} must be an object { host, port?, network? }`)
      const route = item as Record<string, unknown>
      for (const key of Object.keys(route)) if (!["host", "port", "network"].includes(key)) fail(`Unknown ${field} field ${JSON.stringify(key)}`)
      const routeHost = text(route.host, `${field}.host`, 253) ?? fail(`${field}.host is required`)
      if (!HOST.test(routeHost) || routeHost.includes("%")) fail(`${field}.host ${JSON.stringify(routeHost)} is not a hostname or IP address`)
      const network = text(route.network, `${field}.network`, 64)
      if (network !== undefined && !CIDR.test(network)) fail(`${field}.network ${JSON.stringify(network)} must be a CIDR range like 192.168.0.0/24`)
      return { host: routeHost, ...(route.port !== undefined && route.port !== null && { port: port(route.port, `${field}.port`) }), ...(network !== undefined && { network }) }
    })
  }
  const reachability = text(raw.reachability, "ssh.reachability", 200)
  const forwardX11 = flag(raw.forwardX11, "ssh.forwardX11")
  const forwardX11Trusted = flag(raw.forwardX11Trusted, "ssh.forwardX11Trusted")
  const forwardAgent = flag(raw.forwardAgent, "ssh.forwardAgent")
  return {
    host, auth,
    ...(user !== undefined && { user }),
    ...(raw.port !== undefined && raw.port !== null && { port: port(raw.port, "ssh.port") }),
    ...(proxyJump !== undefined && { proxyJump }),
    ...(identityFile !== undefined && { identityFile }),
    ...(identityAgent !== undefined && { identityAgent }),
    ...(forwardX11 !== undefined && { forwardX11 }),
    ...(forwardX11Trusted !== undefined && { forwardX11Trusted }),
    ...(forwardAgent !== undefined && { forwardAgent }),
    ...(localForwards?.length && { localForwards }),
    ...(remoteForwards?.length && { remoteForwards }),
    ...(interval !== undefined && interval !== null && { serverAliveInterval: interval as number }),
    ...(options && Object.keys(options).length && { options }),
    ...(routes?.length && { routes }),
    ...(reachability !== undefined && { reachability }),
  }
}

/** Validates a complete machine. Unknown fields are rejected so typos surface instead of being ignored. */
export function normalizeMachine(input: unknown, now = new Date()): Machine {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("machine must be an object")
  const raw = input as Record<string, unknown>
  for (const key of Object.keys(raw)) if (!["id", "label", "os", "ssh", "publicKey", "notes", "updatedAt"].includes(key)) fail(`Unknown machine field ${JSON.stringify(key)}`)
  const id = validMachineId(raw.id)
  const os = (raw.os ?? "linux") as Os
  if (os !== "linux" && os !== "macos") fail("os must be linux or macos")
  const label = text(raw.label, "label", 120)
  const notes = typeof raw.notes === "string" && raw.notes.length <= 4000 ? raw.notes : raw.notes === undefined || raw.notes === null ? undefined : fail("notes must be text up to 4000 characters")
  const publicKey = text(raw.publicKey, "publicKey", 1000)
  if (publicKey !== undefined && !PUBLIC_KEY.test(publicKey)) fail("publicKey must be an ssh-ed25519 public key")
  return {
    id, os,
    ...(label !== undefined && { label }),
    ...(raw.ssh !== undefined && raw.ssh !== null && { ssh: normalizeSsh(raw.ssh, id) }),
    ...(publicKey !== undefined && { publicKey }),
    ...(notes && { notes }),
    updatedAt: now.toISOString(),
  }
}

export function normalizeEnvVar(input: unknown, now = new Date()): EnvVar {
  if (!input || typeof input !== "object" || Array.isArray(input)) return fail("env var must be an object")
  const raw = input as Record<string, unknown>
  for (const key of Object.keys(raw)) if (!["name", "description", "secret", "value", "updatedAt"].includes(key)) fail(`Unknown env field ${JSON.stringify(key)}`)
  const name = validEnvName(raw.name)
  const description = text(raw.description, "description", 300) ?? fail(`${name} needs a description of what it is for`)
  const secret = flag(raw.secret, "secret") ?? false
  if (secret && raw.value !== undefined && raw.value !== null) {
    fail(`${name} is secret: do not pass its value. Ask the user to enter it with machine_request_secret.`)
  }
  if (!secret && (raw.value === undefined || raw.value === null)) fail(`${name} needs a value (or set secret: true)`)
  if (!secret && (typeof raw.value !== "string" || raw.value.length > 32 * 1024 || raw.value.includes("\0"))) fail(`${name} value must be a string up to 32 KiB`)
  return { name, description, secret, ...(!secret && { value: raw.value as string }), updatedAt: now.toISOString() }
}

/**
 * Merges a partial update into an existing record: top-level and `ssh` fields are merged and `null` clears a field.
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

export function mergeEnvVar(existing: EnvVar | undefined, patch: Record<string, unknown>): Record<string, unknown> {
  const base: Record<string, unknown> = existing ? { ...existing } : {}
  delete base.updatedAt
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete base[key]
    else base[key] = value
  }
  // Becoming secret drops the plain value; becoming plain needs a new value from the patch.
  if (base.secret === true && !("value" in patch)) delete base.value
  return base
}
