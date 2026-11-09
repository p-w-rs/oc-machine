import type { Machine } from "./model.js"

export const SSH_CONFIG_VAR = "OCM_SSH_CONFIG"

export interface ShellEnvInput {
  readonly local?: Machine
  /** Effect of the `*` row for `env.<NAME>` on the local machine. */
  readonly allowed: (name: string) => boolean
  /** Decrypted secret env values of the local machine, keyed by variable name. */
  readonly secrets: ReadonlyMap<string, string>
  readonly sshConfigPath?: string
}

/**
 * Variables to add to a new agent shell. Purely additive: a variable the shell already has is kept unless the
 * machine marks it `override`. Unset secrets are skipped rather than exported empty.
 */
export function shellAdditions(input: ShellEnvInput, existing: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const additions: Record<string, string> = {}
  if (input.sshConfigPath && existing[SSH_CONFIG_VAR] === undefined) additions[SSH_CONFIG_VAR] = input.sshConfigPath
  for (const variable of input.local?.env ?? []) {
    if (!input.allowed(variable.name)) continue
    if (existing[variable.name] !== undefined && !variable.override) continue
    const value = variable.secret ? input.secrets.get(variable.name) : variable.value
    if (value !== undefined) additions[variable.name] = value
  }
  return additions
}
