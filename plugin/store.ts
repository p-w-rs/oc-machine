import { stat } from "node:fs/promises"
import { join } from "node:path"
import { atomicWrite, ensurePrivateDir, readJson, Serial, withFileLock } from "oc-secure-kit"
import { MACHINES_FORMAT, normalizeEnvVar, normalizeMachine, type EnvVar, type Machine } from "./model.js"

interface MachinesFile {
  format: typeof MACHINES_FORMAT
  revision: number
  machines: Record<string, Machine>
  env: Record<string, EnvVar>
}
/** Per-install state that is never exported: which machine is the computer OpenCode runs on. */
interface LocalFile { format: "oc-machine-local/1"; localMachine?: string }

const empty = (): MachinesFile => ({ format: MACHINES_FORMAT, revision: 0, machines: {}, env: {} })
const byKey = <T>(record: Record<string, T>) => Object.entries(record).sort(([a], [b]) => a.localeCompare(b)).map(([, value]) => value)

export class MachineStore {
  readonly path: string
  readonly localPath: string
  #file: MachinesFile = empty()
  #local: LocalFile = { format: "oc-machine-local/1" }
  #stamp = ""
  #serial = new Serial()
  #listeners = new Set<() => void>()

  private constructor(dir: string) {
    this.path = join(dir, "machines.json")
    this.localPath = join(dir, "local.json")
  }

  static async open(dir: string): Promise<MachineStore> {
    await ensurePrivateDir(dir)
    const store = new MachineStore(dir)
    await store.reload()
    return store
  }

  /** Re-reads both files when either changed on disk (e.g. another OpenCode server). Returns true when something changed. */
  async reload(): Promise<boolean> {
    const stamps = await Promise.all([this.path, this.localPath].map(async path => {
      try { const info = await stat(path); return `${info.mtimeMs}:${info.size}:${info.ino}` }
      catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing"; throw error }
    }))
    const stamp = stamps.join("|")
    if (stamp === this.#stamp) return false
    const file = await readJson<MachinesFile>(this.path) ?? empty()
    if (file.format !== MACHINES_FORMAT || typeof file.machines !== "object" || !file.machines) throw new Error(`Unsupported machines file: ${this.path}`)
    file.env ??= {}
    this.#file = file
    this.#local = await readJson<LocalFile>(this.localPath) ?? { format: "oc-machine-local/1" }
    const changed = this.#stamp !== ""
    this.#stamp = stamp
    if (changed) this.#emit()
    return true
  }

  /** Last loaded machines and env vars, without touching the disk (for synchronous hooks and tool descriptions). */
  cached(): { machines: Machine[]; env: EnvVar[]; localMachine?: string } {
    const local = this.#local.localMachine
    return { machines: byKey(this.#file.machines), env: byKey(this.#file.env), ...(local && this.#file.machines[local] && { localMachine: local }) }
  }

  async list(): Promise<Machine[]> { await this.reload(); return byKey(this.#file.machines) }
  async get(id: string): Promise<Machine | undefined> { await this.reload(); return this.#file.machines[id] }
  async listEnv(): Promise<EnvVar[]> { await this.reload(); return byKey(this.#file.env) }
  async getEnv(name: string): Promise<EnvVar | undefined> { await this.reload(); return this.#file.env[name] }

  async localMachine(): Promise<string | undefined> {
    await this.reload()
    const id = this.#local.localMachine
    return id && this.#file.machines[id] ? id : undefined
  }

  /** Saves a machine (validated). With `rename`, the machine moves from that ID to `machine.id`. */
  put(machine: Machine, rename?: string): Promise<Machine> {
    const checked = normalizeMachine(machine)
    return this.#mutate(file => {
      if (rename !== undefined && rename !== checked.id) {
        if (!file.machines[rename]) throw new Error(`No machine ${rename}`)
        if (file.machines[checked.id]) throw new Error(`Machine ${checked.id} already exists`)
        delete file.machines[rename]
        for (const other of Object.values(file.machines)) {
          const hops = other.ssh?.proxyJump?.split(",")
          if (hops?.includes(rename)) {
            file.machines[other.id] = { ...other, ssh: { ...other.ssh!, proxyJump: hops.map(hop => hop === rename ? checked.id : hop).join(",") } }
          }
        }
      }
      file.machines[checked.id] = checked
      return checked
    }, local => { if (rename !== undefined && local.localMachine === rename) local.localMachine = checked.id })
  }

  remove(id: string): Promise<boolean> {
    return this.#mutate(file => {
      if (!file.machines[id]) return false
      const users = Object.values(file.machines).filter(other => other.ssh?.proxyJump?.split(",").includes(id)).map(other => other.id)
      if (users.length) throw new Error(`${id} is the jump host for ${users.join(", ")}; change their proxyJump first`)
      delete file.machines[id]
      return true
    }, local => { if (local.localMachine === id) delete local.localMachine })
  }

  setLocal(id: string | undefined): Promise<void> {
    return this.#mutate(file => {
      if (id !== undefined && !file.machines[id]) throw new Error(`No machine ${id}`)
    }, local => { if (id === undefined) delete local.localMachine; else local.localMachine = id })
  }

  putEnv(variable: EnvVar, rename?: string): Promise<EnvVar> {
    const checked = normalizeEnvVar(variable)
    return this.#mutate(file => {
      if (rename !== undefined && rename !== checked.name) {
        if (!file.env[rename]) throw new Error(`No env var ${rename}`)
        if (file.env[checked.name]) throw new Error(`Env var ${checked.name} already exists`)
        delete file.env[rename]
      }
      file.env[checked.name] = checked
      return checked
    })
  }

  removeEnv(name: string): Promise<boolean> {
    return this.#mutate(file => {
      if (!file.env[name]) return false
      delete file.env[name]
      return true
    })
  }

  /** Machines and env vars, for export. */
  async exportAll(): Promise<{ machines: Record<string, Machine>; env: Record<string, EnvVar> }> {
    await this.reload()
    return structuredClone({ machines: this.#file.machines, env: this.#file.env })
  }

  /** Adds or replaces machines and env vars from an import. `replaceAll` drops entries not in the import. */
  importAll(input: { machines: Record<string, Machine>; env: Record<string, EnvVar> }, replaceAll = false): Promise<void> {
    const machines = Object.values(input.machines).map(machine => normalizeMachine(machine))
    const env = Object.values(input.env).map(variable => normalizeEnvVar(variable))
    return this.#mutate(file => {
      if (replaceAll) { file.machines = {}; file.env = {} }
      for (const machine of machines) file.machines[machine.id] = machine
      for (const variable of env) file.env[variable.name] = variable
    }, local => { if (local.localMachine && replaceAll && !machines.some(machine => machine.id === local.localMachine)) delete local.localMachine })
  }

  /** Called after any change, including changes made by another process (detected on the next read). */
  onChange(listener: () => void): () => void {
    this.#listeners.add(listener)
    return () => { this.#listeners.delete(listener) }
  }

  #emit(): void { for (const listener of this.#listeners) { try { listener() } catch {} } }

  #mutate<T>(change: (file: MachinesFile) => T, changeLocal?: (local: LocalFile) => void): Promise<T> {
    return this.#serial.run(() => withFileLock(this.path, async () => {
      this.#stamp = ""
      await this.reload()
      const file = structuredClone(this.#file)
      const local = structuredClone(this.#local)
      const result = change(file)
      changeLocal?.(local)
      file.revision += 1
      await atomicWrite(this.path, JSON.stringify(file, null, 2) + "\n")
      if (JSON.stringify(local) !== JSON.stringify(this.#local)) await atomicWrite(this.localPath, JSON.stringify(local, null, 2) + "\n")
      this.#stamp = ""
      await this.reload()
      this.#emit()
      return result
    }))
  }
}
