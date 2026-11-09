import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { atomicWrite, PolicyStore, Redactor, SecretRequests, Vault, type Effect } from "oc-secure-kit"
import { capabilities, defaultEffect, secretSlots, type Machine } from "./model.js"
import { shellAdditions } from "./shellenv.js"
import { renderConfig, type SshPolicy } from "./sshconfig.js"
import { MachineStore } from "./store.js"

export const PLUGIN_ID = "oc-machine"

/** Everything the plugin keeps on disk, opened from one private data directory. */
export class MachineService {
  readonly dir: string
  readonly sshConfigPath: string
  readonly keysDir: string
  readonly redactor = new Redactor()

  private constructor(
    dir: string,
    readonly store: MachineStore,
    readonly vault: Vault,
    readonly policy: PolicyStore,
    readonly requests: SecretRequests,
  ) {
    this.dir = dir
    this.sshConfigPath = join(dir, "ssh_config")
    this.keysDir = join(dir, "keys")
  }

  static async open(dir: string): Promise<MachineService> {
    const [store, vault, policy, requests] = await Promise.all([
      MachineStore.open(dir), Vault.open({ dir, plugin: PLUGIN_ID }), PolicyStore.open(dir), SecretRequests.open(dir),
    ])
    const service = new MachineService(dir, store, vault, policy, requests)
    await service.refreshRedactor()
    vault.onChange(() => { service.#redactorStale = true })
    return service
  }

  #redactorStale = false

  /** Brings the redactor up to date with the vault, including changes made by other processes. Cheap when unchanged. */
  async syncRedactor(): Promise<void> {
    await this.vault.list() // stat check; marks the redactor stale when the file changed
    if (this.#redactorStale) {
      this.#redactorStale = false
      await this.refreshRedactor()
    }
  }

  /** Effect of the any-agent (`*`) row, which governs the agent's own shell. */
  async anyAgentEffect(machineId: string, capability: string): Promise<Effect> {
    return (await this.policy.resolve({ entity: machineId, capability, fallback: defaultEffect(capability) })).effect
  }

  async shellPolicy(machineId: string): Promise<SshPolicy> {
    // The shell cannot show a prompt, so only "allow" counts there.
    const [ssh, x11, agentForward] = await Promise.all(["ssh", "x11", "agent-forward"].map(async capability => (await this.anyAgentEffect(machineId, capability)) === "allow"))
    return { ssh: ssh!, x11: x11!, agentForward: agentForward! }
  }

  async renderSshConfig(): Promise<string> {
    const machines = await this.store.list()
    const policies = new Map(await Promise.all(machines.map(async machine => [machine.id, await this.shellPolicy(machine.id)] as const)))
    return renderConfig(machines, { keysDir: this.keysDir, policy: id => policies.get(id) ?? { ssh: false, x11: false, agentForward: false } })
  }

  /** Rewrites the plugin's ssh_config when its content changed. Never touches ~/.ssh/config. */
  async writeSshConfig(): Promise<string> {
    const text = await this.renderSshConfig()
    let current: string | undefined
    try { current = await readFile(this.sshConfigPath, "utf8") } catch {}
    if (current !== text) await atomicWrite(this.sshConfigPath, text)
    return text
  }

  /** Variables to add to a new agent shell (local machine env vars the `*` row allows, plus OCM_SSH_CONFIG). */
  async shellAdditions(existing: Readonly<Record<string, string | undefined>>): Promise<Record<string, string>> {
    await this.writeSshConfig()
    const localId = await this.store.localMachine()
    const local = localId ? await this.store.get(localId) : undefined
    const allowed = new Map<string, boolean>()
    const secrets = new Map<string, string>()
    for (const variable of local?.env ?? []) {
      const ok = (await this.anyAgentEffect(local!.id, `env.${variable.name}`)) === "allow"
      allowed.set(variable.name, ok)
      if (ok && variable.secret) {
        const value = await this.vault.get(local!.id, `env:${variable.name}`)
        if (value !== undefined) secrets.set(variable.name, value)
      }
    }
    return shellAdditions({ local, allowed: name => allowed.get(name) ?? false, secrets, sshConfigPath: this.sshConfigPath }, existing)
  }

  async secretStatus(machine: Machine): Promise<Record<string, "set" | "unset">> {
    const stored = new Set((await this.vault.list(machine.id)).map(item => item.name))
    return Object.fromEntries(secretSlots(machine).map(slot => [slot, stored.has(slot) ? "set" : "unset"]))
  }

  /** Deletes vault entries and permission columns a machine no longer uses (e.g. a removed env var). */
  async pruneOrphans(machine: Machine): Promise<void> {
    const slots = new Set<string>(secretSlots(machine))
    for (const item of await this.vault.list(machine.id)) if (!slots.has(item.name)) await this.vault.delete(machine.id, item.name)
    const columns = new Set<string>(capabilities(machine))
    const used = new Set<string>()
    const doc = await this.policy.reload()
    for (const row of Object.values(doc.entities[machine.id]?.agents ?? {})) for (const capability of Object.keys(row)) used.add(capability)
    for (const session of Object.values(doc.sessions)) for (const capability of Object.keys(session.entities[machine.id] ?? {})) used.add(capability)
    for (const capability of used) if (!columns.has(capability)) await this.policy.removeCapability(machine.id, capability)
  }

  async refreshRedactor(): Promise<void> {
    const values = await this.vault.values()
    this.redactor.replaceAll(values.map(item => [`${item.entity}/${item.name}`, item.value] as const))
  }
}
