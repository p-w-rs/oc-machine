// Adds this plugin to the global OpenCode config (comment-preserving, with a backup).
//   (default)    install an immutable snapshot under $XDG_DATA_HOME/oc-machine/releases
//   --dev        point OpenCode at this checkout instead
//   --uninstall  remove only this plugin's entry; data, vault and snapshots are kept
import { spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmod, copyFile, mkdir, readFile, rename, rm, unlink, writeFile } from "node:fs/promises"
import { homedir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import { applyEdits, modify, parse } from "jsonc-parser"

const NAME = "oc-machine"
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const args = process.argv.slice(2)
if (args.length > 1 || args.some(arg => !["--dev", "--uninstall"].includes(arg))) throw new Error("Usage: install.mjs [--dev | --uninstall]")
const dev = args.includes("--dev")
const uninstall = args.includes("--uninstall")
if (!["darwin", "linux"].includes(process.platform)) throw new Error(`${NAME} supports macOS and Linux only`)

const releases = join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), NAME, "releases")
const configDir = join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "opencode")
await mkdir(configDir, { recursive: true })

const run = (cmd, argv, cwd) => {
  const result = spawnSync(cmd, argv, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] })
  if (result.error || result.status !== 0) throw result.error || new Error(`${cmd} ${argv[0]} failed (${result.status})`)
  return result.stdout
}

async function snapshot() {
  const scratch = join(root, ".local", "pack")
  await mkdir(scratch, { recursive: true })
  const [info] = JSON.parse(run("npm", ["pack", "--json", "--pack-destination", scratch, "--cache", ".local/npm-cache"], root))
  const tarball = join(scratch, info.filename)
  const digest = createHash("sha256").update(await readFile(tarball)).digest("hex").slice(0, 12)
  const target = join(releases, `${info.version}-${digest}`)
  try { await readFile(join(target, ".complete")); return target } catch {}
  const staging = `${target}.${process.pid}.tmp`
  await mkdir(staging, { recursive: true, mode: 0o700 })
  try {
    run("tar", ["-xzf", tarball, "-C", staging, "--strip-components=1"], root)
    run("npm", ["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", join(root, ".local", "npm-cache")], staging)
    await writeFile(join(staging, ".complete"), new Date().toISOString() + "\n")
    await rename(staging, target)
  } catch (error) { await rm(staging, { recursive: true, force: true }); throw error }
  return target
}

const guard = join(configDir, `.${NAME}-install.lock`)
try { await writeFile(guard, String(process.pid), { flag: "wx", mode: 0o600 }) }
catch (error) {
  if (error.code === "EEXIST") throw new Error(`Another ${NAME} install holds ${guard}. If a prior run crashed, confirm it stopped before removing the lock.`)
  throw error
}
try {
  let path = join(configDir, "opencode.jsonc")
  let source
  for (const name of ["opencode.jsonc", "opencode.json"]) {
    try { source = await readFile(join(configDir, name), "utf8"); path = join(configDir, name); break }
    catch (error) { if (error.code !== "ENOENT") throw error }
  }
  const existed = source !== undefined
  source ??= '{\n  "$schema": "https://opencode.ai/config.json"\n}\n'
  const errors = []
  const config = parse(source, errors, { allowTrailingComma: true })
  if (errors.length || !config || typeof config !== "object" || Array.isArray(config)) throw new Error(`Invalid config: ${path}`)
  const plugins = config.plugins ?? []
  if (!Array.isArray(plugins)) throw new Error(`Expected a V2 plugins array in ${path}; refusing to rewrite it.`)

  const target = uninstall ? undefined : dev ? root : await snapshot()
  const entryPath = entry => typeof entry === "string" ? entry : entry?.package
  const owned = plugins.flatMap((entry, index) => {
    const p = entryPath(entry)
    return typeof p === "string" && (p === root || p.startsWith(`${releases}/`)) ? [index] : []
  })
  const done = uninstall ? owned.length === 0 : owned.length === 1 && entryPath(plugins[owned[0]]) === target
  if (!done) {
    const format = { formattingOptions: { insertSpaces: true, tabSize: 2 } }
    let updated = source
    if (uninstall) for (const index of [...owned].reverse()) updated = applyEdits(updated, modify(updated, ["plugins", index], undefined, format))
    else if (!Array.isArray(config.plugins)) updated = applyEdits(updated, modify(updated, ["plugins"], [target], format))
    else if (!owned.length) updated = applyEdits(updated, modify(updated, ["plugins", plugins.length], target, format))
    else {
      const first = owned[0]
      // Keep any existing options object; only the package path changes.
      updated = applyEdits(updated, modify(updated, typeof plugins[first] === "string" ? ["plugins", first] : ["plugins", first, "package"], target, format))
      for (const index of owned.slice(1).reverse()) updated = applyEdits(updated, modify(updated, ["plugins", index], undefined, format))
    }
    if (existed) {
      if (await readFile(path, "utf8") !== source) throw new Error("OpenCode configuration changed during installation; retry.")
      const backup = `${path}.${NAME}-${Date.now()}.bak`
      await copyFile(path, backup)
      await chmod(backup, 0o600)
    }
    const temporary = `${path}.${NAME}-${process.pid}.tmp`
    await writeFile(temporary, updated, { mode: 0o600, flag: "wx" })
    await rename(temporary, path)
  }
  if (uninstall) console.log(`${NAME} ${done ? "already absent from" : "removed from"} ${path}. Data, vault and snapshots were kept.`)
  else console.log(`${NAME} ${done ? "already installed" : "installed"} in ${path}\nPlugin: ${target}${dev ? " (development link)" : " (snapshot)"}\nUse /reload in OpenCode if needed.`)
} finally { await unlink(guard) }
