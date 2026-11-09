import { randomBytes } from "node:crypto"
import { mkdir, readdir, rm, stat, writeFile } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"
import { ensurePrivateDir } from "oc-secure-kit"

/** How long per-command files outlive the command (background jobs may still be connecting). */
export const RUN_DIR_GRACE_MS = 30_000
/** Leftovers from crashes are removed after this. */
const STALE_MS = 15 * 60_000

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

/** A private directory of files for one command: ssh config, materialized keys and askpass answers. */
export class RunDir {
  private constructor(readonly path: string) {}

  static async create(base: string): Promise<RunDir> {
    await ensurePrivateDir(base)
    const path = join(base, `${Date.now().toString(36)}-${randomBytes(6).toString("hex")}`)
    await mkdir(path, { mode: 0o700 })
    return new RunDir(path)
  }

  /** Removes leftovers of commands that never finished (crash, killed server). Never throws. */
  static async sweep(base: string, now = Date.now()): Promise<void> {
    try {
      for (const name of await readdir(base)) {
        const path = join(base, name)
        try { if (now - (await stat(path)).mtimeMs > STALE_MS) await rm(path, { recursive: true, force: true }) } catch {}
      }
    } catch {}
  }

  file(name: string): string { return join(this.path, name) }

  async write(name: string, content: string, mode = 0o600): Promise<string> {
    const path = this.file(name)
    await writeFile(path, content, { mode, flag: "wx" })
    return path
  }

  /** Writes a materialized private key at `keys/<id>`. ssh refuses keys readable by others, so mode is 0600. */
  async writeKey(id: string, privateKey: string): Promise<string> {
    await mkdir(this.file("keys"), { recursive: true, mode: 0o700 })
    return this.write(join("keys", id), privateKey.endsWith("\n") ? privateKey : `${privateKey}\n`)
  }

  get keysDir(): string { return this.file("keys") }

  /** Writes the ssh askpass helper and its answers; returns the helper path. */
  async writeSshAskpass(answers: readonly AskpassAnswer[]): Promise<string> {
    const lines: string[] = []
    for (const [index, answer] of answers.entries()) {
      if (/[\t\n]/.test(answer.match)) throw new Error("askpass match cannot contain tabs or newlines")
      const name = `answer.${index}`
      await this.write(name, answer.value)
      lines.push(`${answer.kind}\t${answer.kind === "passphrase" ? expandHome(answer.match) : answer.match}\t${name}`)
    }
    await this.write("askpass.map", lines.join("\n") + "\n")
    const passwords = answers.filter(answer => answer.kind === "password")
    if (passwords.length === 1) await this.write("password.only", passwords[0]!.value)
    return this.write("askpass", SSH_ASKPASS, 0o700)
  }

  async writeSudoAskpass(password: string): Promise<string> {
    await this.write("sudo.secret", password)
    return this.write("sudo-askpass", SUDO_ASKPASS, 0o700)
  }

  async remove(): Promise<void> { await rm(this.path, { recursive: true, force: true }) }

  /** Removes the directory after the grace period, without keeping the process alive. */
  removeLater(ms = RUN_DIR_GRACE_MS): void {
    setTimeout(() => { void this.remove().catch(() => {}) }, ms).unref()
  }
}
