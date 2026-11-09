import { SSH_CONFIG_VAR } from "./references.js"
import type { MachineService, Supply } from "./service.js"

/** Native tools that run shell commands; their `input.command` is matched to the shell they start. */
export const SHELL_TOOLS = new Set(["shell", "bash"])
/** A supply not picked up by a shell within this time is discarded (e.g. the native permission was rejected). */
const PENDING_MS = 10 * 60_000

interface Pending { readonly callID: string; readonly supply: Supply; readonly at: number }
interface BeforeEvent { readonly tool: string; readonly sessionID: string; readonly agent: string; readonly messageID: string; readonly id: string; input: unknown }
interface CreateEvent { readonly command: string; env: Record<string, string | undefined> }
interface AfterEvent { readonly tool: string; readonly id: string; readonly input: unknown; readonly status: "completed" | "error"; result?: unknown; error?: unknown }

const commandOf = (input: unknown) =>
  input && typeof input === "object" && typeof (input as { command?: unknown }).command === "string" ? (input as { command: string }).command : undefined

/** Appends a note to a native shell result without changing its structure. */
export function appendNote(result: unknown, note: string): unknown {
  if (!result || typeof result !== "object") return result
  const copy = { ...(result as Record<string, unknown>) }
  const line = `[oc-machine] ${note}`
  const join = (text: string) => `${text}${text === "" || text.endsWith("\n") ? "" : "\n"}${line}`
  if (typeof copy.content === "string") copy.content = join(copy.content)
  else if (Array.isArray(copy.content)) {
    const content = [...copy.content]
    const last = content.findLastIndex(part => part && typeof part === "object" && (part as { type?: unknown }).type === "text")
    if (last >= 0) content[last] = { ...content[last], text: join((content[last] as { text: string }).text) }
    else content.push({ type: "text", text: line })
    copy.content = content
  }
  if (copy.output && typeof copy.output === "object" && typeof (copy.output as { output?: unknown }).output === "string") {
    copy.output = { ...(copy.output as object), output: join((copy.output as { output: string }).output) }
  }
  return copy
}

const exitCode = (result: unknown): number | undefined => {
  const output = result && typeof result === "object" ? (result as { output?: unknown }).output : undefined
  const exit = output && typeof output === "object" ? (output as { exit?: unknown }).exit : undefined
  return typeof exit === "number" ? exit : undefined
}

/**
 * Supplies values to native shell commands that reference them. `before` (tool hook, knows session and agent, awaited
 * by the host) checks permissions and prepares; `create` (shell hook, ~1 ms later, same command string) adds the
 * values to that shell; `after` masks secrets and adds notes. Every step is a no-op for commands that reference
 * nothing of ours, and none of them ever blocks or fails a command.
 */
export class NativeShell {
  #pending = new Map<string, Pending[]>()
  #byCall = new Map<string, Pending>()

  constructor(private readonly service: MachineService, private readonly warn: (message: string, error?: unknown) => void) {}

  async before(event: BeforeEvent): Promise<void> {
    if (!SHELL_TOOLS.has(event.tool)) return
    const command = commandOf(event.input)
    if (!command) return
    let supply: Supply | undefined
    try {
      supply = await this.service.prepareCommand(command, {
        sessionID: event.sessionID, agent: event.agent, source: { type: "tool", messageID: event.messageID, id: event.id },
      })
    } catch (error) {
      this.warn("could not prepare shell values", error)
      return
    }
    if (!supply) return
    this.#expire()
    const pending: Pending = { callID: event.id, supply, at: Date.now() }
    this.#pending.set(command, [...this.#pending.get(command) ?? [], pending])
    this.#byCall.set(event.id, pending)
  }

  create(event: CreateEvent): void {
    try {
      const queue = this.#pending.get(event.command)
      const pending = queue?.shift()
      if (!queue?.length) this.#pending.delete(event.command)
      if (pending) Object.assign(event.env, pending.supply.env)
    } catch (error) { this.warn("could not add shell values", error) }
  }

  after(event: AfterEvent): void {
    if (!SHELL_TOOLS.has(event.tool)) return
    try {
      const pending = this.#byCall.get(event.id)
      this.#byCall.delete(event.id)
      if (pending) {
        const command = commandOf(event.input)
        if (command) {
          const queue = this.#pending.get(command)?.filter(item => item !== pending)
          if (queue?.length) this.#pending.set(command, queue); else this.#pending.delete(command)
        }
        pending.supply.runDir?.removeLater()
      }
      if (event.status !== "completed") {
        if (pending?.supply.secrets && event.error instanceof Error) {
          try { event.error.message = this.service.redactor.redact(event.error.message) } catch {}
        }
        return
      }
      let result = event.result
      if (pending?.supply.secrets) result = this.service.redactor.redactDeep(result)
      for (const note of pending?.supply.notes ?? []) result = appendNote(result, note)
      if (!pending && exitCode(result) !== 0) {
        const tip = this.#sshTip(commandOf(event.input) ?? "")
        if (tip) result = appendNote(result, tip)
      }
      event.result = result
    } catch (error) { this.warn("could not finish shell values", error) }
  }

  /** When a plain `ssh gpu-2` fails, point at the plugin's config. Synchronous and cached-data only. */
  #sshTip(command: string): string | undefined {
    if (command.includes(SSH_CONFIG_VAR) || !/(?:^|[\s;&|(])(ssh|scp|sftp|rsync)\b/.test(command)) return undefined
    const ids = this.service.knownSshMachines().filter(id => new RegExp(`(?<![A-Za-z0-9._/-])${id.replace(/[.]/g, "\\.")}(?![A-Za-z0-9._-])`).test(command))
    return ids.length ? `${ids.join(", ")} ${ids.length > 1 ? "are" : "is an"} oc-machine host${ids.length > 1 ? "s" : ""}: use ssh -F "$${SSH_CONFIG_VAR}" ${ids[0]} ...` : undefined
  }

  #expire(): void {
    const cutoff = Date.now() - PENDING_MS
    for (const [command, queue] of this.#pending) {
      const fresh = queue.filter(item => {
        if (item.at >= cutoff) return true
        this.#byCall.delete(item.callID)
        void item.supply.runDir?.remove().catch(() => {})
        return false
      })
      if (fresh.length) this.#pending.set(command, fresh); else this.#pending.delete(command)
    }
  }

  dispose(): void {
    for (const pending of this.#byCall.values()) void pending.supply.runDir?.remove().catch(() => {})
    this.#pending.clear()
    this.#byCall.clear()
  }
}
