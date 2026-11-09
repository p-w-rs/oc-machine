import type { Machine } from "./model.js"
import { withJumpHosts } from "./sshconfig.js"

export const SSH_CONFIG_VAR = "OCM_SSH_CONFIG"
export const SUDO_PASSWORD_VAR = "OCM_SUDO_PASSWORD"

export interface References {
  /** Defined env vars the command mentions as `$NAME` or `${NAME...}`. */
  readonly env: string[]
  /** The command uses `$OCM_SSH_CONFIG`. */
  readonly sshConfig: boolean
  /** Machines named in the command (only when it uses `$OCM_SSH_CONFIG`). */
  readonly targets: string[]
  /** `targets` plus their jump hosts: every machine the per-command config must contain. */
  readonly sshMachines: string[]
  /** The command uses `$OCM_SUDO_PASSWORD`. */
  readonly sudoPassword: boolean
  /** Machine whose sudo password `$OCM_SUDO_PASSWORD` means, or why there is none. */
  readonly sudoTarget?: { readonly machine: string } | { readonly problem: string }
  /** The command runs `sudo -A` / `sudo --askpass` on this computer. */
  readonly sudoAskpass: boolean
}

const VAR_REF = /\$\{?([A-Za-z_][A-Za-z0-9_]*)/g
const escape = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

export function referencedVariables(command: string): Set<string> {
  return new Set([...command.matchAll(VAR_REF)].map(match => match[1]!))
}

/**
 * Finds what a shell command asks the plugin for. Purely textual and deliberately generous: a false positive only
 * means a permission check (or prompt) for something the command did not need; nothing is ever blocked.
 */
export function analyzeCommand(command: string, input: {
  readonly envNames: ReadonlySet<string>
  readonly machines: readonly Machine[]
  readonly localMachine?: string
}): References {
  const vars = referencedVariables(command)
  const env = [...vars].filter(name => input.envNames.has(name)).sort()
  const sshConfig = vars.has(SSH_CONFIG_VAR)
  const all = new Map(input.machines.map(machine => [machine.id, machine] as const))
  const targets = !sshConfig ? [] : input.machines
    .filter(machine => machine.ssh && new RegExp(`(?<![A-Za-z0-9._/-])${escape(machine.id)}(?![A-Za-z0-9._-])`).test(command))
    .map(machine => machine.id)
  const sshMachines = withJumpHosts(targets, all).filter(id => all.get(id)?.ssh)
  const sudoPassword = vars.has(SUDO_PASSWORD_VAR)
  let sudoTarget: References["sudoTarget"]
  if (sudoPassword) {
    if (targets.length === 1) sudoTarget = { machine: targets[0]! }
    else if (targets.length > 1) sudoTarget = { problem: `$${SUDO_PASSWORD_VAR} is ambiguous: the command targets ${targets.join(", ")}. Use one machine per command.` }
    else if (input.localMachine) sudoTarget = { machine: input.localMachine }
    else sudoTarget = { problem: `$${SUDO_PASSWORD_VAR} needs an ssh target in the command, or a machine marked local (this computer).` }
  }
  const sudoAskpass = /(?:^|[\s;&|(`])sudo\b[^;&|\n]*?\s(?:-[A-Za-z]*A[A-Za-z]*|--askpass)(?=\s|$)/.test(command)
  return { env, sshConfig, targets, sshMachines, sudoPassword, ...(sudoTarget && { sudoTarget }), sudoAskpass }
}

/** Nothing for the plugin to do: the command runs exactly as in plain OpenCode. */
export function isEmpty(references: References): boolean {
  return !references.env.length && !references.sshConfig && !references.sudoPassword && !references.sudoAskpass
}
