import { spawn } from "node:child_process"
import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { Machine } from "./model.js"

/** What the permission table allows for the agent's own shell (the `*` row). */
export interface SshPolicy {
  readonly ssh: boolean
  readonly x11: boolean
  readonly agentForward: boolean
}

export interface RenderOptions {
  /** Directory holding materialized generated keys (`<keysDir>/<id>`) for this command. */
  readonly keysDir: string
  readonly policy: (machineId: string) => SshPolicy
  /** ssh understands `Match localnetwork` (OpenSSH 9.4+); without it, routes rely on the reachability probe alone. */
  readonly localNetwork?: boolean
}

/** A one-second TCP check, used by `Match exec` to pick a route (macOS nc needs -G; without nc, bash /dev/tcp). */
export function probeCommand(host: string, port: number): string {
  return `if command -v nc >/dev/null 2>&1; then if [ $(uname) = Darwin ]; then nc -z -G 1 -w 1 ${host} ${port}; else nc -z -w 1 ${host} ${port}; fi; else timeout 1 bash -c '</dev/tcp/${host}/${port}'; fi >/dev/null 2>&1`
}

function quote(value: string): string {
  if (/^[^\s"'#\\]+$/.test(value)) return value
  if (value.includes('"')) throw new Error(`ssh_config value cannot contain a double quote: ${value}`)
  return `"${value}"`
}

/** One `Host` block. Pure; secrets never appear (passwords are supplied by plugin tools, not the file). */
export function renderHost(machine: Machine, all: ReadonlyMap<string, Machine>, options: RenderOptions): string | undefined {
  const ssh = machine.ssh
  if (!ssh) return undefined
  const policy = options.policy(machine.id)
  if (!policy.ssh) return undefined
  const lines: string[] = [`# ${machine.label ? machine.label.replace(/[\r\n]/g, " ") : machine.id}${ssh.reachability ? ` (reachable from: ${ssh.reachability.replace(/[\r\n]/g, " ")})` : ""}`]
  // Preferred routes first: ssh keeps the first value it sees, so a matching route's HostName/Port win.
  for (const route of ssh.routes ?? []) {
    const network = route.network && options.localNetwork !== false ? ` localnetwork ${route.network}` : ""
    lines.push(`Match originalhost ${machine.id}${network} exec "${probeCommand(route.host, route.port ?? 22)}"`, `  HostName ${route.host}`, `  Port ${route.port ?? 22}`)
  }
  lines.push(`Host ${machine.id}`)
  const set = (name: string, value: string | number | undefined) => { if (value !== undefined) lines.push(`  ${name} ${quote(String(value))}`) }
  const custom = new Set(Object.keys(ssh.options ?? {}).map(name => name.toLowerCase()))
  set("HostName", ssh.host)
  set("User", ssh.user)
  set("Port", ssh.port)
  if (ssh.proxyJump) {
    // Hops that name another machine with ssh allowed resolve through this same file's Host blocks.
    for (const hop of ssh.proxyJump.split(",")) {
      const target = all.get(hop)
      if (target && !(target.ssh && options.policy(hop).ssh)) throw new Error(`${machine.id} jumps through ${hop}, which has no ssh access`)
    }
    set("ProxyJump", ssh.proxyJump)
  }
  switch (ssh.auth) {
    case "key":
      set("IdentityFile", ssh.identityFile)
      set("IdentitiesOnly", "yes")
      break
    case "generated":
      set("IdentityFile", join(options.keysDir, machine.id))
      set("IdentitiesOnly", "yes")
      break
    case "password":
      set("PreferredAuthentications", "keyboard-interactive,password")
      set("PubkeyAuthentication", "no")
      break
    case "agent":
      set("IdentityAgent", ssh.identityAgent)
      break
  }
  set("ForwardX11", ssh.forwardX11 && policy.x11 ? "yes" : ssh.forwardX11 !== undefined || !policy.x11 ? "no" : undefined)
  if (ssh.forwardX11 && policy.x11 && ssh.forwardX11Trusted !== undefined) set("ForwardX11Trusted", ssh.forwardX11Trusted ? "yes" : "no")
  set("ForwardAgent", ssh.forwardAgent && policy.agentForward ? "yes" : ssh.forwardAgent !== undefined || !policy.agentForward ? "no" : undefined)
  for (const forward of ssh.localForwards ?? []) lines.push(`  LocalForward ${forward.replace(/:(?=[^:]+:\d+$)/, " ")}`)
  for (const forward of ssh.remoteForwards ?? []) lines.push(`  RemoteForward ${forward.replace(/:(?=[^:]+:\d+$)/, " ")}`)
  set("ServerAliveInterval", ssh.serverAliveInterval)
  for (const [name, value] of Object.entries(ssh.options ?? {})) set(name, value)
  // Every route reaches the same machine: one host key entry, so a wrong machine on a route is still rejected.
  if (ssh.routes?.length && !custom.has("hostkeyalias")) set("HostKeyAlias", machine.id)
  // Fail fast when the machine is out of reach (VPN off, other network) instead of ssh's long default.
  if (!custom.has("connecttimeout")) set("ConnectTimeout", 10)
  // Agents cannot answer ssh's interactive yes/no for a new host; trust on first use, still reject changed keys.
  if (!Object.keys(ssh.options ?? {}).some(name => name.toLowerCase() === "stricthostkeychecking")) set("StrictHostKeyChecking", "accept-new")
  return lines.join("\n")
}

export function renderConfig(machines: readonly Machine[], options: RenderOptions): string {
  const all = new Map(machines.map(machine => [machine.id, machine]))
  // One bad machine must not take the whole file (and every other host) down with it.
  const blocks = [...machines].sort((a, b) => a.id.localeCompare(b.id)).flatMap(machine => {
    try {
      const block = renderHost(machine, all, options)
      return block ? [block] : []
    } catch (error) {
      return [`# ${machine.id} skipped: ${(error as Error).message.replace(/[\r\n]/g, " ")}`]
    }
  })
  return [
    "# Generated by oc-machine. Do not edit: changes are overwritten.",
    "# Use: ssh -F \"$OCM_SSH_CONFIG\" <machine-id>",
    "",
    ...blocks.flatMap(block => [block, ""]),
  ].join("\n")
}

/** Machines a set of targets needs: the targets plus every jump host that is itself a configured machine. */
export function withJumpHosts(targets: Iterable<string>, all: ReadonlyMap<string, Machine>): string[] {
  const result = new Set<string>()
  const visit = (id: string) => {
    if (result.has(id) || !all.has(id)) return
    result.add(id)
    for (const hop of all.get(id)!.ssh?.proxyJump?.split(",") ?? []) visit(hop)
  }
  for (const id of targets) visit(id)
  return [...result]
}

export interface SshResult { readonly code: number | null; readonly stdout: string; readonly stderr: string }

export function runSsh(args: readonly string[], options: { ssh?: string; timeoutMs?: number; env?: NodeJS.ProcessEnv; input?: string } = {}): Promise<SshResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(options.ssh ?? "ssh", args, { stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"], env: options.env ?? process.env, detached: true })
    if (options.input !== undefined) child.stdin!.end(options.input)
    let stdout = "", stderr = ""
    child.stdout!.on("data", chunk => { if (stdout.length < 1_000_000) stdout += chunk })
    child.stderr!.on("data", chunk => { if (stderr.length < 1_000_000) stderr += chunk })
    // ssh may hand off to an askpass helper or ProxyJump child; kill the whole group on timeout.
    const timer = setTimeout(() => { try { process.kill(-child.pid!, "SIGKILL") } catch { child.kill("SIGKILL") } }, options.timeoutMs ?? 10_000)
    child.on("error", error => { clearTimeout(timer); reject(error) })
    child.on("close", code => { clearTimeout(timer); resolve({ code, stdout, stderr }) })
  })
}

/**
 * Validates config text with `ssh -G` (parses the file and prints the resolved options without connecting).
 * Returns the resolved options for each host alias.
 */
export async function validateConfig(text: string, hosts: readonly string[], ssh?: string): Promise<Map<string, Map<string, string[]>>> {
  const dir = await mkdtemp(join(tmpdir(), "oc-machine-ssh-"))
  try {
    const file = join(dir, "config")
    await writeFile(file, text, { mode: 0o600 })
    const resolved = new Map<string, Map<string, string[]>>()
    for (const host of hosts.length ? hosts : ["oc-machine-validate"]) {
      const result = await runSsh(["-G", "-F", file, host], { ssh })
      if (result.code !== 0) throw new Error(`ssh rejected the generated config for ${host}: ${result.stderr.trim() || `exit ${result.code}`}`)
      const options = new Map<string, string[]>()
      for (const line of result.stdout.split("\n")) {
        const match = /^(\S+)\s+(.*)$/.exec(line)
        if (match) options.set(match[1]!, [...options.get(match[1]!) ?? [], match[2]!])
      }
      resolved.set(host, options)
    }
    return resolved
  } finally { await rm(dir, { recursive: true, force: true }) }
}

const UNREACHABLE = /timed out|Operation timed out|No route to host|Network is unreachable|Could not resolve hostname|nodename nor servname|Name or service not known|Connection refused/i

/** A hint when ssh could not reach a machine that is only reachable from some networks. */
export function unreachableHint(output: string, machine: Machine): string | undefined {
  if (!UNREACHABLE.test(output)) return undefined
  const ssh = machine.ssh
  if (ssh?.reachability) return `${machine.id} could not be reached. It is only reachable from: ${ssh.reachability}. Ask the user to connect (e.g. the VPN), then retry; don't change its settings.`
  if (ssh?.routes?.length) return `${machine.id} could not be reached on any route (${[...ssh.routes.map(route => route.host), ssh.host].join(", ")}). The machine may be off or this network blocked; ask the user.`
  return undefined
}
