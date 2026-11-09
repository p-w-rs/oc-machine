import type { EnvVar, Machine } from "./model.js"
import { SSH_CONFIG_VAR, SUDO_PASSWORD_VAR } from "./references.js"

const MAX_MACHINES = 40
const MAX_ENV = 80
const clip = (text: string, max: number) => text.length > max ? `${text.slice(0, max - 1)}…` : text

/** Usage the agent needs to use the plugin from its own shell. */
export const USAGE = [
  `Use these from your normal shell tool; values are supplied to that one command after a permission check (it may ask the user).`,
  `- Env vars: reference them by name, e.g. $HF_TOKEN. On a remote machine: ssh -F "$${SSH_CONFIG_VAR}" gpu-2 "HF_TOKEN=$HF_TOKEN cmd".`,
  `- SSH/scp/rsync: ssh -F "$${SSH_CONFIG_VAR}" <machine-id> ...  (rsync -e 'ssh -F "$${SSH_CONFIG_VAR}"' ...). Keys, jump hosts and passwords are handled.`,
  `- sudo on this computer: sudo -A cmd. On a remote machine: printf '%s\\n' "$${SUDO_PASSWORD_VAR}" | ssh -F "$${SSH_CONFIG_VAR}" <id> "sudo -S -p '' cmd".`,
  `Never print or echo secret values.`,
].join("\n")

/** Names and descriptions only, never values. Short enough for a tool description. */
export function inventory(machines: readonly Machine[], env: readonly EnvVar[], localMachine?: string): string {
  const lines: string[] = []
  if (!machines.length && !env.length) return "No machines or env vars are configured yet. Set them up with machine_upsert and machine_env_set."
  if (machines.length) {
    lines.push("Machines:")
    for (const machine of machines.slice(0, MAX_MACHINES)) {
      const how = machine.id === localMachine ? "this computer" : machine.ssh ? "ssh" : "no ssh"
      lines.push(`  ${machine.id} (${machine.os}, ${how})${machine.label ? ` ${clip(machine.label, 60)}` : ""}`)
    }
    if (machines.length > MAX_MACHINES) lines.push(`  …and ${machines.length - MAX_MACHINES} more (machine_list)`)
  }
  if (env.length) {
    lines.push("Env vars (usable on any machine):")
    for (const variable of env.slice(0, MAX_ENV)) lines.push(`  ${variable.name}${variable.secret ? " [secret]" : ""}: ${clip(variable.description, 100)}`)
    if (env.length > MAX_ENV) lines.push(`  …and ${env.length - MAX_ENV} more (machine_list)`)
  }
  return lines.join("\n")
}
