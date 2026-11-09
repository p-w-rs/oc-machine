import { join } from "node:path"
import { PolicyStore, Redactor, SecretRequests, Vault, type PermissionBridge } from "oc-secure-kit"
import { defaultEffect, ENV_VALUE, envEntity, machineSlots, type EnvVar, type Machine } from "./model.js"
import { analyzeCommand, isEmpty, SSH_CONFIG_VAR, SUDO_PASSWORD_VAR, type References } from "./references.js"
import { RunDir, type AskpassAnswer } from "./rundir.js"
import { renderConfig } from "./sshconfig.js"
import { MachineStore } from "./store.js"

export const PLUGIN_ID = "oc-machine"

/** Who is asking: the calling session and agent, plus the tool call for the native prompt. */
export interface Caller {
  readonly sessionID: string
  readonly agent?: string
  readonly source?: { type: "tool"; messageID: string; id: string }
}

/** What the plugin supplies to one shell command. */
export interface Supply {
  /** Variables to add to that shell's environment. */
  readonly env: Record<string, string>
  /** One-line explanations for the agent (denied, declined, missing secrets). */
  readonly notes: string[]
  /** Secret values were supplied, so the command's output is masked. */
  readonly secrets: boolean
  readonly runDir?: RunDir
}

/** Machines and env vars on disk, plus the vault, permission table and secret requests. */
export class MachineService {
  readonly dir: string
  readonly runBase: string
  readonly redactor = new Redactor()
  #bridge?: PermissionBridge
  #redactorStale = false

  private constructor(
    dir: string,
    readonly store: MachineStore,
    readonly vault: Vault,
    readonly policy: PolicyStore,
    readonly requests: SecretRequests,
  ) {
    this.dir = dir
    this.runBase = join(dir, "run")
  }

  static async open(dir: string): Promise<MachineService> {
    const [store, vault, policy, requests] = await Promise.all([
      MachineStore.open(dir), Vault.open({ dir, plugin: PLUGIN_ID }), PolicyStore.open(dir), SecretRequests.open(dir),
    ])
    const service = new MachineService(dir, store, vault, policy, requests)
    await service.refreshRedactor()
    vault.onChange(() => { service.#redactorStale = true })
    await RunDir.sweep(service.runBase)
    return service
  }

  knownSshMachines(): string[] { return this.store.cached().machines.filter(machine => machine.ssh).map(machine => machine.id) }

  attach(bridge: PermissionBridge): void { this.#bridge = bridge }
  get bridge(): PermissionBridge {
    if (!this.#bridge) throw new Error(`${PLUGIN_ID}: permissions are not set up`)
    return this.#bridge
  }

  /** The full (unfiltered) generated config, for display. Secrets never appear in it. */
  async renderFullConfig(): Promise<string> {
    return renderConfig(await this.store.list(), { keysDir: "<per-command>/keys", policy: () => ({ ssh: true, x11: true, agentForward: true }) })
  }

  /**
   * Checks a capability on several entities with one native prompt. Entities the table denies are dropped without
   * asking; the rest are checked together. Returns the granted entities; reasons for the others go into `notes`.
   */
  async grant(caller: Caller, capability: string, entities: readonly string[], notes: string[], what: (entity: string) => string, metadata?: Record<string, unknown>): Promise<Set<string>> {
    const granted = new Set<string>()
    if (!entities.length) return granted
    const effects = await Promise.all(entities.map(async entity =>
      [entity, (await this.bridge.effect({ sessionID: caller.sessionID, agent: caller.agent, capability, entity })).effect] as const))
    const denied = effects.filter(([, effect]) => effect === "deny").map(([entity]) => entity)
    if (denied.length) notes.push(`${denied.map(what).join(", ")}: ${capability} denied by the Machines permission table (the user can change it).`)
    // Allowed entities are checked without a prompt (native config denies still apply); only "ask" ones are shown to the user.
    for (const wanted of ["allow", "ask"] as const) {
      const group = effects.filter(([, effect]) => effect === wanted).map(([entity]) => entity)
      if (!group.length) continue
      try {
        await this.bridge.check({ ...caller, capability, entities: group, ...(metadata && { metadata }) })
        for (const entity of group) granted.add(entity)
      } catch (error) {
        notes.push(`${group.map(what).join(", ")}: ${capability} not granted (${(error as Error).message.split("\n")[0]}).`)
      }
    }
    return granted
  }

  /**
   * Works out what a native shell command references, checks permissions (prompting for **ask**), and prepares the
   * values. Returns undefined when the command references nothing of ours, so it runs exactly as in plain OpenCode.
   */
  async prepareCommand(command: string, caller: Caller): Promise<Supply | undefined> {
    const [envVars, machines, localMachine] = await Promise.all([this.store.listEnv(), this.store.list(), this.store.localMachine()])
    const references = analyzeCommand(command, { envNames: new Set(envVars.map(variable => variable.name)), machines, localMachine })
    if (isEmpty(references)) return undefined
    return this.#supply(references, caller, { envVars, machines, command })
  }

  /** Prepares ssh access to machines for a command the plugin itself runs (machine_test, key install). */
  async prepareSsh(targets: readonly string[], caller: Caller, purpose: string): Promise<Supply> {
    const machines = await this.store.list()
    const references = analyzeCommand(`ssh -F "$${SSH_CONFIG_VAR}" ${targets.join(" ")}`, { envNames: new Set(), machines })
    return this.#supply(references, caller, { envVars: [], machines, command: purpose })
  }

  async #supply(references: References, caller: Caller, input: { envVars: EnvVar[]; machines: Machine[]; command: string }): Promise<Supply> {
    const notes: string[] = []
    const env: Record<string, string> = {}
    let secrets = false
    let runDir: RunDir | undefined
    const metadata = { command: input.command.length > 500 ? `${input.command.slice(0, 500)}…` : input.command }
    const all = new Map(input.machines.map(machine => [machine.id, machine] as const))
    try {
      // Env vars: one prompt for every referenced variable that is not denied.
      const vars = new Map(input.envVars.map(variable => [variable.name, variable] as const))
      const usable = await this.grant(caller, "use", references.env.map(envEntity), notes, entity => `$${entity.slice(4)}`, metadata)
      for (const name of references.env) {
        if (!usable.has(envEntity(name))) continue
        const variable = vars.get(name)!
        const value = variable.secret ? await this.vault.get(envEntity(name), ENV_VALUE) : variable.value
        if (value === undefined) { notes.push(`$${name} has no value yet: ask the user to enter it (machine_request_secret env=${name}).`); continue }
        env[name] = value
        secrets ||= variable.secret
      }

      // ssh: a per-command config with only the granted machines, their keys and askpass answers.
      if (references.sshConfig) {
        runDir = await RunDir.create(this.runBase)
        if (!references.targets.length) notes.push(`No configured machine is named in this command; $${SSH_CONFIG_VAR} is empty. Machines: ${input.machines.filter(machine => machine.ssh).map(machine => machine.id).join(", ") || "(none)"}.`)
        const ssh = await this.grant(caller, "ssh", references.sshMachines, notes, id => id, metadata)
        const wanting = (flag: "forwardX11" | "forwardAgent") => [...ssh].filter(id => all.get(id)?.ssh?.[flag])
        const x11 = await this.grant(caller, "x11", wanting("forwardX11"), notes, id => id)
        const agentForward = await this.grant(caller, "agent-forward", wanting("forwardAgent"), notes, id => id)
        const answers: AskpassAnswer[] = []
        for (const id of ssh) {
          const machine = all.get(id)!.ssh!
          if (machine.auth === "generated") {
            const key = await this.vault.get(id, "ssh-key")
            if (key) { await runDir.writeKey(id, key); secrets = true }
            else notes.push(`${id} uses a generated key that does not exist yet: run machine_ssh_keygen.`)
          } else if (machine.auth === "password") {
            const password = await this.vault.get(id, "ssh-password")
            if (password) { answers.push({ kind: "password", match: machine.host, value: password }); secrets = true }
            else notes.push(`${id}'s ssh password is not set: ask the user (machine_request_secret id=${id} slot=ssh-password).`)
          } else if (machine.auth === "key") {
            const passphrase = await this.vault.get(id, "key-passphrase")
            if (passphrase) { answers.push({ kind: "passphrase", match: machine.identityFile!, value: passphrase }); secrets = true }
          }
        }
        const config = renderConfig(input.machines, {
          keysDir: runDir.keysDir,
          policy: id => ({ ssh: ssh.has(id), x11: x11.has(id), agentForward: agentForward.has(id) }),
        })
        env[SSH_CONFIG_VAR] = await runDir.write("ssh_config", config)
        if (answers.length) {
          env.SSH_ASKPASS = await runDir.writeSshAskpass(answers)
          env.SSH_ASKPASS_REQUIRE = "force"
        }
      }

      // sudo: $OCM_SUDO_PASSWORD for the one targeted machine, and/or sudo -A on this computer.
      const sudoMachines = new Set<string>()
      if (references.sudoTarget && "problem" in references.sudoTarget) notes.push(references.sudoTarget.problem)
      const passwordTarget = references.sudoTarget && "machine" in references.sudoTarget ? references.sudoTarget.machine : undefined
      if (passwordTarget) sudoMachines.add(passwordTarget)
      const local = await this.store.localMachine()
      if (references.sudoAskpass) {
        if (local) sudoMachines.add(local)
        else notes.push("sudo -A needs a machine marked local (this computer) with a sudo password.")
      }
      const sudo = await this.grant(caller, "sudo", [...sudoMachines], notes, id => id, metadata)
      for (const id of sudo) {
        const password = await this.vault.get(id, "sudo")
        if (!password) { notes.push(`${id}'s sudo password is not set: ask the user (machine_request_secret id=${id} slot=sudo).`); continue }
        secrets = true
        if (id === passwordTarget) env[SUDO_PASSWORD_VAR] = password
        if (references.sudoAskpass && id === local) {
          runDir ??= await RunDir.create(this.runBase)
          env.SUDO_ASKPASS = await runDir.writeSudoAskpass(password)
        }
      }
      if (secrets) await this.syncRedactor()
      return { env, notes, secrets, ...(runDir && { runDir }) }
    } catch (error) {
      await runDir?.remove().catch(() => {})
      throw error
    }
  }

  async machineSecretStatus(machine: Machine): Promise<Record<string, "set" | "unset">> {
    const stored = new Set((await this.vault.list(machine.id)).map(item => item.name))
    return Object.fromEntries(machineSlots(machine).map(slot => [slot, stored.has(slot) ? "set" : "unset"]))
  }

  async envStatus(variable: EnvVar): Promise<"set" | "unset"> {
    if (!variable.secret) return "set"
    return await this.vault.has(envEntity(variable.name), ENV_VALUE) ? "set" : "unset"
  }

  /** Deletes vault entries a machine no longer uses (e.g. after switching auth). */
  async pruneMachineSecrets(machine: Machine): Promise<void> {
    const slots = new Set<string>(machineSlots(machine))
    for (const item of await this.vault.list(machine.id)) if (!slots.has(item.name)) await this.vault.delete(machine.id, item.name)
  }

  /** Effect of a capability for a caller, without prompting. */
  async effect(caller: Caller, capability: string, entity: string) {
    return (await this.bridge.effect({ sessionID: caller.sessionID, agent: caller.agent, capability, entity })).effect
  }

  /** Brings the redactor up to date with the vault, including changes by other processes. Cheap when unchanged. */
  async syncRedactor(): Promise<void> {
    await this.vault.list()
    if (this.#redactorStale) {
      this.#redactorStale = false
      await this.refreshRedactor()
    }
  }

  async refreshRedactor(): Promise<void> {
    const values = await this.vault.values()
    this.redactor.replaceAll(values.map(item => [item.name === ENV_VALUE ? item.entity : `${item.entity}/${item.name}`, item.value] as const))
  }
}

export { defaultEffect }
