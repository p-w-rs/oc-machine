import { spawn } from "node:child_process"
import { readFile } from "node:fs/promises"
import type { ToolContext } from "@opencode/plugin/promise/tool"
import { ENV_VALUE, envEntity, isFillableSlot, machineSlots, mergeEnvVar, mergeMachine, normalizeEnvVar, normalizeMachine, validEnvName, type Machine } from "./model.js"
import { inventory, USAGE } from "./inventory.js"
import { SSH_CONFIG_VAR } from "./references.js"
import type { Caller, MachineService } from "./service.js"
import { RunDir } from "./rundir.js"
import { renderHost, runSsh, validateConfig } from "./sshconfig.js"

export const TOOL_NAMES = [
  "machine_list", "machine_get", "machine_upsert", "machine_remove", "machine_env_set", "machine_env_remove",
  "machine_request_secret", "machine_ssh_keygen", "machine_test", "machine_ssh_config",
] as const

export interface ToolDefinition {
  readonly name: (typeof TOOL_NAMES)[number]
  /** Rebuilt on every tool reload, so the inventory stays current. */
  readonly description: () => string
  readonly input: Record<string, unknown>
  readonly execute: (input: any, context: ToolContext) => Promise<{ content: string; metadata?: Record<string, unknown> }>
}

const ID = { type: "string", minLength: 1, maxLength: 64, pattern: "^[A-Za-z0-9][A-Za-z0-9._-]*$", description: "Machine ID; also the ssh Host alias" }
const ENV_NAME = { type: "string", pattern: "^[A-Za-z_][A-Za-z0-9_]*$" }

const SSH_SCHEMA = {
  type: "object",
  description: "SSH settings. Fields merge into the existing ssh settings; null clears a field.",
  properties: {
    host: { type: "string", description: "Hostname or IP" },
    user: { type: "string" },
    port: { type: "integer", minimum: 1, maximum: 65535 },
    proxyJump: { type: "string", description: "Another machine ID or [user@]host[:port]; comma-separated for chains" },
    auth: { type: "string", enum: ["agent", "key", "password", "generated"], description: "agent: ssh-agent / 1Password / Secretive; key: a key file (optional passphrase secret); password: the user enters it; generated: a per-machine key from machine_ssh_keygen" },
    identityFile: { type: "string", description: "Private key path for auth=key (~ allowed)" },
    identityAgent: { type: "string", description: "Agent socket for auth=agent, if not $SSH_AUTH_SOCK" },
    forwardX11: { type: "boolean" },
    forwardX11Trusted: { type: "boolean" },
    forwardAgent: { type: "boolean" },
    localForwards: { type: "array", items: { type: "string" }, description: "e.g. 8080:localhost:80 or 127.0.0.1:5432:db:5432" },
    remoteForwards: { type: "array", items: { type: "string" } },
    serverAliveInterval: { type: "integer", minimum: 0, maximum: 3600 },
    options: { type: "object", additionalProperties: { type: "string" }, description: "Other ssh_config options, e.g. {\"Compression\":\"yes\"}" },
  },
} as const

const json = (value: unknown) => ({ content: JSON.stringify(value, null, 2) })
const callerOf = (context: ToolContext): Caller => ({
  sessionID: context.sessionID, agent: context.agent, source: { type: "tool", messageID: context.messageID, id: context.id },
})

function run(command: string, args: string[]): Promise<{ code: number | null; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ["ignore", "ignore", "pipe"] })
    let stderr = ""
    child.stderr.on("data", chunk => { stderr += chunk })
    child.on("error", reject)
    child.on("close", code => resolve({ code, stderr }))
  })
}

export function createTools(service: MachineService): ToolDefinition[] {
  const check = (context: ToolContext, capability: string, entity: string, metadata?: Record<string, unknown>) =>
    service.bridge.check({ ...callerOf(context), capability, entities: [entity], ...(metadata && { metadata }) })

  const requireMachine = async (id: string) => {
    const machine = await service.store.get(id)
    if (!machine) throw new Error(`No machine ${JSON.stringify(id)}. Machines: ${(await service.store.list()).map(item => item.id).join(", ") || "(none)"}`)
    return machine
  }

  const summary = async (machine: Machine, local: string | undefined) => ({
    id: machine.id,
    ...(machine.label && { label: machine.label }),
    os: machine.os,
    ...(machine.id === local && { local: true }),
    ...(machine.ssh && { ssh: `${machine.ssh.user ? `${machine.ssh.user}@` : ""}${machine.ssh.host}${machine.ssh.port ? `:${machine.ssh.port}` : ""} (${machine.ssh.auth})`, connect: `ssh -F "$${SSH_CONFIG_VAR}" ${machine.id}` }),
    secrets: await service.machineSecretStatus(machine),
  })

  /** Runs ssh from the plugin itself (test, key install) with the same per-command config the shell gets. */
  const pluginSsh = async (context: ToolContext, id: string, remote: string, purpose: string) => {
    const supply = await service.prepareSsh([id], callerOf(context), purpose)
    try {
      if (!supply.env[SSH_CONFIG_VAR] || supply.notes.some(note => note.includes("not granted") || note.includes("denied"))) {
        return { ok: false as const, error: supply.notes.join(" ") || "ssh is not available for this machine" }
      }
      const result = await runSsh(["-F", supply.env[SSH_CONFIG_VAR]!, "-o", "ConnectTimeout=15", "-o", "BatchMode=no", id, remote], {
        env: { ...process.env, ...supply.env }, timeoutMs: 45_000,
      })
      const redact = (text: string) => service.redactor.redact(text.trim())
      return { ok: result.code === 0, code: result.code, stdout: redact(result.stdout), stderr: redact(result.stderr), notes: supply.notes }
    } finally { await supply.runDir?.remove().catch(() => {}) }
  }

  return [
    {
      name: "machine_list",
      description: () => {
        const { machines, env, localMachine } = service.store.cached()
        return `Machines and env vars the user configured for you, and how to use them.\n${inventory(machines, env, localMachine)}\n${USAGE}\nCall this tool for details: which secrets are set and what you are allowed to do.`
      },
      input: { type: "object", properties: {}, additionalProperties: false },
      execute: async (_input, context) => {
        const local = await service.store.localMachine()
        const machines = await Promise.all((await service.store.list()).map(machine => summary(machine, local)))
        const env = await Promise.all((await service.store.listEnv()).map(async variable => ({
          name: variable.name, description: variable.description, secret: variable.secret,
          status: await service.envStatus(variable),
          use: await service.effect(callerOf(context), "use", envEntity(variable.name)),
        })))
        return json({ machines, env, usage: USAGE })
      },
    },
    {
      name: "machine_get",
      description: () => "Full configuration of one machine, which of its secrets are set, and what you may do on it (allow = just works, ask = the user is prompted, deny = not available). Secret values are never shown.",
      input: { type: "object", properties: { id: ID }, required: ["id"], additionalProperties: false },
      execute: async (input: { id: string }, context) => {
        const machine = await requireMachine(input.id)
        const caller = callerOf(context)
        const permissions = Object.fromEntries(await Promise.all(["ssh", "sudo", "x11", "agent-forward", "manage", "remove"].map(async capability =>
          [capability, await service.effect(caller, capability, machine.id)] as const)))
        return json({
          machine, local: machine.id === await service.store.localMachine(), secrets: await service.machineSecretStatus(machine), permissions,
          ...(machine.ssh && { connect: `ssh -F "$${SSH_CONFIG_VAR}" ${machine.id}` }),
          note: "The user changes permissions in the Machines table; tools cannot.",
        })
      },
    },
    {
      name: "machine_upsert",
      description: () => "Create or update a machine (fields merge; null clears one). Set local=true for the computer OpenCode runs on (used for sudo -A). SSH settings are validated with ssh -G before saving. Never pass secrets here: use machine_request_secret.",
      input: {
        type: "object",
        properties: {
          id: ID,
          rename: { ...ID, description: "New ID for an existing machine" },
          label: { type: ["string", "null"], description: "Short description, e.g. 'A100 training box'" },
          os: { type: "string", enum: ["linux", "macos"] },
          local: { type: "boolean", description: "This is the computer OpenCode runs on" },
          ssh: { anyOf: [SSH_SCHEMA, { type: "null" }] },
          notes: { type: ["string", "null"] },
        },
        required: ["id"],
        additionalProperties: false,
      },
      execute: async (input: Record<string, unknown> & { id: string; rename?: string; local?: boolean }, context) => {
        const { id, rename, local, ...patch } = input
        if ("publicKey" in patch) throw new Error("publicKey is set by machine_ssh_keygen")
        const existing = await service.store.get(id)
        await check(context, "manage", id, { operation: existing ? "update" : "create" })
        if (rename !== undefined && !existing) throw new Error(`Cannot rename: no machine ${id}`)
        if (rename !== undefined && rename !== id) await check(context, "manage", rename, { operation: "rename", from: id })
        const target = rename ?? id
        const candidate = normalizeMachine({ ...mergeMachine(existing, patch), id: target, ...(!existing && !("os" in patch) && { os: "linux" }) })
        if (candidate.ssh) {
          const others = new Map((await service.store.list()).filter(machine => machine.id !== id).map(machine => [machine.id, machine] as const))
          others.set(candidate.id, candidate)
          const block = renderHost(candidate, others, { keysDir: "/keys", policy: () => ({ ssh: true, x11: true, agentForward: true }) })
          await validateConfig(block ?? "", [candidate.id])
        }
        const saved = await service.store.put(candidate, existing && target !== id ? id : undefined)
        if (existing && target !== id) {
          await service.vault.renameEntity(id, target)
          await service.policy.renameEntity(id, target)
          await service.requests.remove({ entity: id })
        }
        await service.pruneMachineSecrets(saved)
        if (local === true) await service.store.setLocal(saved.id)
        if (local === false && (await service.store.localMachine()) === saved.id) await service.store.setLocal(undefined)
        const secrets = await service.machineSecretStatus(saved)
        const next: string[] = []
        if (secrets["ssh-password"] === "unset") next.push(`ask the user for the ssh password (machine_request_secret id=${saved.id} slot=ssh-password)`)
        if (secrets["ssh-key"] === "unset") next.push(`create the key with machine_ssh_keygen id=${saved.id}`)
        return json({
          saved, local: (await service.store.localMachine()) === saved.id, secrets,
          ...(next.length && { next: next.join("; ") }),
          ...(saved.ssh && { connect: `ssh -F "$${SSH_CONFIG_VAR}" ${saved.id}`, test: `machine_test id=${saved.id}` }),
        })
      },
    },
    {
      name: "machine_remove",
      description: () => "Delete a machine with its stored secrets and permission settings. Asks the user by default.",
      input: { type: "object", properties: { id: ID }, required: ["id"], additionalProperties: false },
      execute: async (input: { id: string }, context) => {
        const machine = await requireMachine(input.id)
        await check(context, "remove", machine.id, { secrets: (await service.vault.list(machine.id)).length })
        await service.store.remove(machine.id)
        await service.vault.deleteEntity(machine.id)
        await service.policy.removeEntity(machine.id)
        await service.requests.remove({ entity: machine.id })
        return json({ removed: machine.id })
      },
    },
    {
      name: "machine_env_set",
      description: () => "Create or update a global env var (usable in shell commands on this computer and any machine). Always give a description of what it is for. Secret vars never take a value here: the user enters it (machine_request_secret). Non-secret vars take their value directly.",
      input: {
        type: "object",
        properties: {
          name: ENV_NAME,
          rename: { ...ENV_NAME, description: "New name for an existing variable" },
          description: { type: "string", maxLength: 300, description: "What it is for, e.g. 'Hugging Face read token for model downloads'" },
          secret: { type: "boolean" },
          value: { type: "string", description: "Only for non-secret variables" },
        },
        required: ["name"],
        additionalProperties: false,
      },
      execute: async (input: { name: string; rename?: string } & Record<string, unknown>, context) => {
        const { name, rename, ...patch } = input
        validEnvName(name)
        const existing = await service.store.getEnv(name)
        await check(context, "manage", envEntity(name), { operation: existing ? "update" : "create" })
        if (rename !== undefined && !existing) throw new Error(`Cannot rename: no env var ${name}`)
        const target = rename ?? name
        if (target !== name) await check(context, "manage", envEntity(validEnvName(target)), { operation: "rename", from: name })
        const candidate = normalizeEnvVar({ ...mergeEnvVar(existing, patch), name: target })
        const saved = await service.store.putEnv(candidate, existing && target !== name ? name : undefined)
        if (existing && target !== name) {
          await service.vault.renameEntity(envEntity(name), envEntity(target))
          await service.policy.renameEntity(envEntity(name), envEntity(target))
          await service.requests.remove({ entity: envEntity(name) })
        }
        if (!saved.secret) {
          await service.vault.deleteEntity(envEntity(saved.name))
          await service.requests.remove({ entity: envEntity(saved.name) })
        }
        const status = await service.envStatus(saved)
        return json({
          saved, status,
          ...(status === "unset" && { next: `Ask the user for the value: machine_request_secret env=${saved.name}` }),
          usage: `Reference it as $${saved.name} in your shell commands.`,
        })
      },
    },
    {
      name: "machine_env_remove",
      description: () => "Delete a global env var and its stored value. Asks the user by default.",
      input: { type: "object", properties: { name: ENV_NAME }, required: ["name"], additionalProperties: false },
      execute: async (input: { name: string }, context) => {
        if (!await service.store.getEnv(input.name)) throw new Error(`No env var ${input.name}`)
        await check(context, "remove", envEntity(input.name))
        await service.store.removeEnv(input.name)
        await service.vault.deleteEntity(envEntity(input.name))
        await service.policy.removeEntity(envEntity(input.name))
        await service.requests.remove({ entity: envEntity(input.name) })
        return json({ removed: input.name })
      },
    },
    {
      name: "machine_request_secret",
      description: () => "Ask the user to enter a secret you cannot see: a secret env var's value (env), or a machine's sudo, ssh-password or key-passphrase (id + slot). You only ever learn whether it is set.",
      input: {
        type: "object",
        properties: {
          env: { ...ENV_NAME, description: "A secret env var" },
          id: ID,
          slot: { type: "string", enum: ["sudo", "ssh-password", "key-passphrase"] },
          purpose: { type: "string", maxLength: 300, description: "Why it is needed, shown to the user" },
        },
        additionalProperties: false,
      },
      execute: async (input: { env?: string; id?: string; slot?: string; purpose?: string }, context) => {
        let entity: string, name: string, label: string, command: string
        if (input.env !== undefined) {
          if (input.id !== undefined || input.slot !== undefined) throw new Error("Pass either env, or id and slot")
          const variable = await service.store.getEnv(input.env)
          if (!variable) throw new Error(`No env var ${input.env}; create it first with machine_env_set`)
          if (!variable.secret) throw new Error(`${input.env} is not secret; set its value with machine_env_set`)
          entity = envEntity(variable.name); name = ENV_VALUE; label = `$${variable.name} (${variable.description})`
          command = `pixi run secret-set ${variable.name}`
        } else {
          if (!input.id || !input.slot) throw new Error("Pass env, or id and slot")
          const machine = await requireMachine(input.id)
          if (!isFillableSlot(machine, input.slot)) throw new Error(`${machine.id} has no ${input.slot} secret. Its secrets: ${machineSlots(machine).filter(slot => slot !== "ssh-key").join(", ")}`)
          entity = machine.id; name = input.slot; label = `${input.slot} for ${machine.id}`
          command = `pixi run secret-set ${machine.id} ${input.slot}`
        }
        const request = await service.requests.add({ entity, name, purpose: input.purpose ?? "", sessionID: context.sessionID })
        const already = await service.vault.has(entity, name)
        return json({
          requested: { id: request.id, secret: label },
          status: already ? "set (the user may replace it)" : "unset",
          tellUser: `Please enter ${label} in Settings > Machines, or in a terminal in the oc-machine folder: ${command}`,
        })
      },
    },
    {
      name: "machine_ssh_keygen",
      description: () => "Create a dedicated ed25519 key for a machine (stored encrypted; you never see the private key). With install=true (default) it is added to the machine's authorized_keys using its current login, then the machine switches to auth=generated.",
      input: {
        type: "object",
        properties: { id: ID, install: { type: "boolean", description: "Install with the current login and switch to the new key (default true)" } },
        required: ["id"],
        additionalProperties: false,
      },
      execute: async (input: { id: string; install?: boolean }, context) => {
        const machine = await requireMachine(input.id)
        if (!machine.ssh) throw new Error(`${machine.id} has no ssh settings`)
        await check(context, "manage", machine.id, { operation: "generate ssh key" })
        const install = input.install ?? true
        const scratch = await RunDir.create(service.runBase)
        let privateKey: string, publicKey: string
        try {
          const result = await run("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", `oc-machine:${machine.id}`, "-f", scratch.file("key")])
          if (result.code !== 0) throw new Error(`ssh-keygen failed: ${result.stderr.trim()}`)
          privateKey = await readFile(scratch.file("key"), "utf8")
          publicKey = (await readFile(scratch.file("key.pub"), "utf8")).trim()
        } finally { await scratch.remove() }

        let installed: unknown
        if (install) {
          if (machine.ssh.auth === "generated" && !await service.vault.has(machine.id, "ssh-key")) {
            throw new Error(`${machine.id} has no working login to install the key with. Set a temporary auth (agent, key or password), or use install=false and add the public key yourself.`)
          }
          const remote = `umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && (grep -qxF '${publicKey}' ~/.ssh/authorized_keys || printf '%s\\n' '${publicKey}' >> ~/.ssh/authorized_keys)`
          const result = await pluginSsh(context, machine.id, remote, "install generated ssh key")
          if (!result.ok) throw new Error(`Could not install the key on ${machine.id}: ${"error" in result ? result.error : result.stderr || `exit ${result.code}`}`)
          installed = true
        }
        await service.vault.set(machine.id, "ssh-key", privateKey)
        const updated = install || machine.ssh.auth === "generated"
          ? await service.store.put(normalizeMachine({ ...mergeMachine(machine, { ssh: { auth: "generated" } }), publicKey }))
          : await service.store.put(normalizeMachine({ ...mergeMachine(machine, {}), publicKey }))
        await service.pruneMachineSecrets(updated)
        await service.refreshRedactor()
        const test = install ? await pluginSsh(context, machine.id, "true", "test generated ssh key") : undefined
        return json({
          machine: machine.id, publicKey, installed: installed ?? false, auth: updated.ssh?.auth,
          ...(test && { test: test.ok ? "connected with the new key" : `test failed: ${"error" in test ? test.error : test.stderr}` }),
          ...(!install && { next: `Add the public key to ~/.ssh/authorized_keys on ${machine.id}, then machine_upsert id=${machine.id} ssh={auth:"generated"}` }),
        })
      },
    },
    {
      name: "machine_test",
      description: () => "Connect to a machine over ssh and report whether login works, plus its OS, user and hostname. Uses the same permissions as ssh from your shell.",
      input: { type: "object", properties: { id: ID }, required: ["id"], additionalProperties: false },
      execute: async (input: { id: string }, context) => {
        const machine = await requireMachine(input.id)
        if (!machine.ssh) throw new Error(`${machine.id} has no ssh settings`)
        const started = Date.now()
        const result = await pluginSsh(context, machine.id, "uname -sm; id -un; hostname", "connection test")
        if (!result.ok) return json({ machine: machine.id, ok: false, error: "error" in result ? result.error : result.stderr || `ssh exited ${result.code}`, ...("notes" in result && result.notes?.length && { notes: result.notes }) })
        const [system, user, host] = result.stdout.split("\n")
        return json({ machine: machine.id, ok: true, system, user, hostname: host, ms: Date.now() - started, ...(result.notes?.length && { notes: result.notes }) })
      },
    },
    {
      name: "machine_ssh_config",
      description: () => "Show the ssh config generated for one machine or all (no secrets). For debugging; your shell commands get it automatically via $OCM_SSH_CONFIG.",
      input: { type: "object", properties: { id: ID }, additionalProperties: false },
      execute: async (input: { id?: string }) => {
        const text = await service.renderFullConfig()
        if (!input.id) return json({ config: text })
        await requireMachine(input.id)
        const block = text.split("\n\n").find(part => part.split("\n").includes(`Host ${input.id}`) || part.startsWith(`# ${input.id} skipped`))
        return json({ config: block ?? `${input.id} has no ssh settings` })
      },
    },
  ]
}
