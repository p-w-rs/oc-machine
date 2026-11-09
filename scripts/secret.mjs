// Enter or remove secrets from a terminal (the GUI does the same).
//   pixi run secret-set <ENV_NAME>            value of a secret env var
//   pixi run secret-set <machine> <slot>      slot: sudo | ssh-password | key-passphrase
//   pixi run secret-unset <ENV_NAME> | <machine> <slot>
//   pixi run secret-list                      pending requests and which secrets are set (never values)
// The value is read with echo off from a terminal, or from stdin when piped. Never pass it as an argument.
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { createInterface } from "node:readline"
import { SecretRequests, Vault, pluginDataDir } from "oc-secure-kit"

const PLUGIN = "oc-machine"
const [command, first, second] = process.argv.slice(2)
const dir = pluginDataDir(PLUGIN, process.env.OC_MACHINE_DATA_DIR || undefined)

async function config() {
  try { const file = JSON.parse(await readFile(join(dir, "machines.json"), "utf8")); return { machines: file.machines ?? {}, env: file.env ?? {} } }
  catch (error) { if (error.code === "ENOENT") return { machines: {}, env: {} }; throw error }
}

function readHidden(prompt) {
  if (!process.stdin.isTTY) {
    return new Promise((resolve, reject) => {
      let data = ""
      process.stdin.setEncoding("utf8")
      process.stdin.on("data", chunk => { data += chunk })
      process.stdin.on("end", () => resolve(data.replace(/\r?\n$/, "")))
      process.stdin.on("error", reject)
    })
  }
  return new Promise(resolve => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true })
    let muted = false
    rl._writeToOutput = text => { if (!muted) process.stdout.write(text) }
    rl.question(prompt, answer => { rl.close(); process.stdout.write("\n"); resolve(answer) })
    muted = true
  })
}

const vault = await Vault.open({ dir, plugin: PLUGIN })
const requests = await SecretRequests.open(dir)
const known = await config()

if (command === "list") {
  const pending = await requests.list()
  console.log(pending.length ? "Pending requests:" : "No pending requests.")
  for (const item of pending) console.log(`  ${item.entity} ${item.name}${item.purpose ? `  — ${item.purpose}` : ""}`)
  const stored = await vault.list()
  console.log(stored.length ? "Stored secrets:" : "No stored secrets.")
  for (const item of stored) console.log(`  ${item.entity} ${item.name}  (updated ${item.updatedAt})`)
  process.exit(0)
}

if (!["set", "unset"].includes(command) || !first) {
  console.error("Usage: secret.mjs set|unset <ENV_NAME> | <machine> <slot>   or   secret.mjs list")
  process.exit(2)
}
let entity, name, label
if (second === undefined) {
  const variable = known.env[first]
  if (!variable) { console.error(`No env var ${first}. Known: ${Object.keys(known.env).join(", ") || "(none)"}`); process.exit(1) }
  if (!variable.secret) { console.error(`${first} is not secret; its value is part of the configuration.`); process.exit(1) }
  entity = `env:${first}`; name = "value"; label = `${first} (${variable.description})`
} else {
  if (!known.machines[first]) { console.error(`No machine ${first}. Known: ${Object.keys(known.machines).join(", ") || "(none)"}`); process.exit(1) }
  if (!["sudo", "ssh-password", "key-passphrase"].includes(second)) { console.error(`Unknown slot ${second}: use sudo, ssh-password or key-passphrase`); process.exit(1) }
  entity = first; name = second; label = `${second} for ${first}`
}

if (command === "unset") {
  console.log(await vault.delete(entity, name) ? `Removed ${label}.` : `${label} was not set.`)
  process.exit(0)
}

const value = await readHidden(`${label}: `)
if (!value) { console.error("Empty value; nothing stored."); process.exit(1) }
if (value.length < 6) console.warn("Note: values shorter than 6 characters cannot be masked in command output.")
await vault.set(entity, name, value)
await requests.remove({ entity, name })
console.log(`Stored ${label}. The agent sees it as "set"; the value stays out of the chat.`)
