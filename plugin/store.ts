import { stat } from "node:fs/promises"
import { join } from "node:path"
import { atomicWrite, ensurePrivateDir, readJson, Serial, withFileLock } from "oc-secure-kit"
import { MACHINES_FORMAT, normalizeMachine, type Machine } from "./model.js"

interface MachinesFile { format: typeof MACHINES_FORMAT; revision: number; machines: Record<string, Machine> }
/** Per-install state that is never exported: which machine is the host OpenCode runs on. */
interface LocalFile { format: "oc-machine-local/1"; localMachine?: string }

const empty = (): MachinesFile => ({ format: MACHINES_FORMAT, revision: 0, machines: {} })

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

  /** Re-reads both files when either changed on disk. Returns true when something changed. */
  async reload(): Promise<boolean> {
    const stamps = await Promise.all([this.path, this.localPath].map(async path => {
      try { const info = await stat(path); return `${info.mtimeMs}:${info.size}:${info.ino}` }
      catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing"; throw error }
    }))
    const stamp = stamps.join("|")
    if (stamp === this.#stamp) return false
    const file = await readJson<MachinesFile>(this.path) ?? empty()
    if (file.format !== MACHINES_FORMAT || typeof file.machines !== "object" || !file.machines) throw new Error(`Unsupported machines file: ${this.path}`)
    this.#file = file
    this.#local = await readJson<LocalFile>(this.localPath) ?? { format: "oc-machine-local/1" }
    this.#stamp = stamp
    return true
  }

  async list(): Promise<Machine[]> {
    await this.reload()
    return Object.values(this.#file.machines).sort((a, b) => a.id.localeCompare(b.id))
  }

  async get(id: string): Promise<Machine | undefined> {
    await this.reload()
    return this.#file.machines[id]
  }

  async localMachine(): Promise<string | undefined> {
    await this.reload()
    const id = this.#local.localMachine
    return id && this.#file.machines[id] ? id : undefined
  }

  get revision(): number { return this.#file.revision }

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

  /** Every machine, for export. */
  async exportMachines(): Promise<Record<string, Machine>> {
    await this.reload()
    return structuredClone(this.#file.machines)
  }

  /** Adds or replaces machines from an import. `replaceAll` drops machines not in the import. */
  importMachines(machines: Record<string, Machine>, replaceAll = false): Promise<void> {
    const checked = Object.values(machines).map(machine => normalizeMachine(machine))
    return this.#mutate(file => {
      if (replaceAll) file.machines = {}
      for (const machine of checked) file.machines[machine.id] = machine
    }, local => { if (local.localMachine && replaceAll && !checked.some(machine => machine.id === local.localMachine)) delete local.localMachine })
  }

  onChange(listener: () => void): () => void {
    this.#listeners.add(listener)
    return () => { this.#listeners.delete(listener) }
  }

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
      for (const listener of this.#listeners) { try { listener() } catch {} }
      return result
    }))
  }
}
