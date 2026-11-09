// Enter or remove machine secrets from a terminal (the GUI does the same).
//   pixi run secret-set <machine> <slot>      slot: sudo | ssh-password | key-passphrase | env:<NAME>
//   pixi run secret-unset <machine> <slot>
//   pixi run secret-list                      pending requests and which secrets are set (never values)
// The value is read with echo off from a terminal, or from stdin when piped. Never pass it as an argument.
import { readFile } from "node:fs/promises"
import { join } from "node:path"
import { createInterface } from "node:readline"
import { SecretRequests, Vault, pluginDataDir } from "oc-secure-kit"

const PLUGIN = "oc-machine"
const [command, machine, slot] = process.argv.slice(2)
const dir = pluginDataDir(PLUGIN, process.env.OC_MACHINE_DATA_DIR || undefined)

async function machines() {
  try { return JSON.parse(await readFile(join(dir, "machines.json"), "utf8")).machines ?? {} }
  catch (error) { if (error.code === "ENOENT") return {}; throw error }
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
const known = await machines()

if (command === "list") {
  const pending = await requests.list()
  console.log(pending.length ? "Pending requests:" : "No pending requests.")
  for (const item of pending) console.log(`  ${item.entity} ${item.name}${item.purpose ? `  — ${item.purpose}` : ""}`)
  const stored = await vault.list()
  console.log(stored.length ? "Stored secrets:" : "No stored secrets.")
  for (const item of stored) console.log(`  ${item.entity} ${item.name}  (updated ${item.updatedAt})`)
  process.exit(0)
}

if (!["set", "unset"].includes(command) || !machine || !slot) {
  console.error("Usage: secret.mjs set|unset <machine> <slot>   or   secret.mjs list")
  process.exit(2)
}
if (!known[machine]) { console.error(`No machine ${machine}. Known: ${Object.keys(known).join(", ") || "(none)"}`); process.exit(1) }
if (!/^(sudo|ssh-password|key-passphrase|env:[A-Za-z_][A-Za-z0-9_]*)$/.test(slot)) { console.error(`Unknown slot ${slot}`); process.exit(1) }

if (command === "unset") {
  console.log(await vault.delete(machine, slot) ? `Removed ${machine} ${slot}.` : `${machine} ${slot} was not set.`)
  process.exit(0)
}

const value = await readHidden(`${machine} ${slot}: `)
if (!value) { console.error("Empty value; nothing stored."); process.exit(1) }
if (value.length < 6) console.warn("Note: values shorter than 6 characters cannot be masked in tool output.")
await vault.set(machine, slot, value)
await requests.remove({ entity: machine, name: slot })
console.log(`Stored ${machine} ${slot}. The agent sees it as "set"; the value stays out of the chat.`)
