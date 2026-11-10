import { homedir } from "node:os"
import { join } from "node:path"
import { RunDir } from "oc-secure-kit"

export { RunDir }

export interface AskpassAnswer {
  /** `password`: matched against `user@<host>` in ssh's prompt; `passphrase`: matched against the key path. */
  readonly kind: "password" | "passphrase"
  readonly match: string
  readonly value: string
}

// One script per run dir. It answers ssh's prompt from files beside it; unknown prompts fail (exit 1).
const SSH_ASKPASS = `#!/bin/sh
# oc-machine: answers ssh password/passphrase prompts for one shell command.
d=$(dirname -- "$0")
prompt=$1
tab=$(printf '\\t')
while IFS="$tab" read -r kind match file; do
  case $kind in
    passphrase) case $prompt in *"$match"*) exec cat -- "$d/$file" ;; esac ;;
    password) case $prompt in *"@$match's password"*|*"@$match)"*) exec cat -- "$d/$file" ;; esac ;;
  esac
done < "$d/askpass.map"
case $prompt in *assword*) [ -f "$d/password.only" ] && exec cat -- "$d/password.only" ;; esac
exit 1
`
const SUDO_ASKPASS = `#!/bin/sh
# oc-machine: answers sudo -A for one shell command.
exec cat -- "$(dirname -- "$0")/sudo.secret"
`

export const expandHome = (path: string) => path === "~" ? homedir() : path.startsWith("~/") ? join(homedir(), path.slice(2)) : path

export const keysDir = (run: RunDir) => run.file("keys")

/** A materialized private key at `keys/<id>` (0600: ssh refuses keys readable by others). */
export function writeKey(run: RunDir, id: string, privateKey: string): Promise<string> {
  return run.write(join("keys", id), privateKey.endsWith("\n") ? privateKey : `${privateKey}\n`)
}

/** Writes the ssh askpass helper and its answers; returns the helper path. */
export async function writeSshAskpass(run: RunDir, answers: readonly AskpassAnswer[]): Promise<string> {
  const lines: string[] = []
  for (const [index, answer] of answers.entries()) {
    if (/[\t\n]/.test(answer.match)) throw new Error("askpass match cannot contain tabs or newlines")
    const name = `answer.${index}`
    await run.write(name, answer.value)
    lines.push(`${answer.kind}\t${answer.kind === "passphrase" ? expandHome(answer.match) : answer.match}\t${name}`)
  }
  await run.write("askpass.map", lines.join("\n") + "\n")
  const passwords = answers.filter(answer => answer.kind === "password")
  if (passwords.length === 1) await run.write("password.only", passwords[0]!.value)
  return run.write("askpass", SSH_ASKPASS, 0o700)
}

export async function writeSudoAskpass(run: RunDir, password: string): Promise<string> {
  await run.write("sudo.secret", password)
  return run.write("sudo-askpass", SUDO_ASKPASS, 0o700)
}
