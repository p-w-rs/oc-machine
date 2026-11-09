// End-to-end check against a real OpenCode CLI (pinned version) in an isolated home, driven by a scripted local model
// (not a real LLM) and a throwaway sshd on 127.0.0.1. Verifies: tools load and run, the inventory in the tool
// description updates live, native shell commands get env vars and ssh only when they reference them, denied values
// are skipped with a note, and secrets are masked in output. Run with: node --import tsx scripts/smoke-host.mjs
import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises"
import { createServer } from "node:http"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { PolicyStore, Vault } from "oc-secure-kit"
import { startSshd } from "../plugin/testsshd.ts"

const OPENCODE_VERSION = "2.2.6"
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const cliPackage = `@opencode/cli-${process.platform}-${process.arch}`
const hostDir = path.join(root, ".local", "host")
const binary = path.join(hostDir, "node_modules", cliPackage, "bin", "opencode")
try { await access(binary) } catch {
  console.log(`Installing ${cliPackage}@${OPENCODE_VERSION} into .local/host ...`)
  await mkdir(hostDir, { recursive: true })
  const result = spawnSync("npm", ["install", "--no-save", "--no-package-lock", "--ignore-scripts", "--prefix", hostDir, "--cache", path.join(root, ".local", "npm-cache"), `${cliPackage}@${OPENCODE_VERSION}`], { stdio: "inherit" })
  if (result.status !== 0) throw new Error(`Could not install ${cliPackage}@${OPENCODE_VERSION}`)
}

const base = await mkdtemp(path.join(await realpath(os.tmpdir()), "oc-machine-smoke-"))
const home = path.join(base, "home"), workspace = path.join(base, "workspace")
await mkdir(workspace, { recursive: true }); await mkdir(path.join(home, "config", "opencode"), { recursive: true })
const dataDir = path.join(home, "data", "oc-machine")
// --snapshot: load a verified installed snapshot (built into this scratch home) instead of the checkout.
let pluginPath = root
if (process.argv.includes("--snapshot")) {
  process.env.XDG_DATA_HOME = path.join(home, "data")
  const { deploy, verifyRelease } = await import("./install.mjs")
  pluginPath = await deploy()
  await verifyRelease(pluginPath)
  console.log(`Using snapshot ${pluginPath}`)
}
const SECRET = "smoke-secret-value-8c1f"
const sshd = await startSshd()

// What the user did beforehand (GUI / pixi run secret-set): stored secrets and one deny cell.
const vault = await Vault.open({ dir: dataDir, plugin: "oc-machine" })
await vault.set("env:SMOKE_SECRET", "value", SECRET)
await vault.set("env:SMOKE_DENIED", "value", "denied-value-0000")
await vault.set("box", "key-passphrase", sshd.passphrase)
await (await PolicyStore.open(dataDir)).setCells([{ entity: "env:SMOKE_DENIED", row: { agent: "*" }, capability: "use", effect: "deny" }])

const calls = [
  { name: "machine_env_set", input: { name: "SMOKE_PLAIN", description: "Plain smoke value", value: "plain-value" } },
  { name: "machine_env_set", input: { name: "SMOKE_SECRET", description: "Smoke test API token", secret: true } },
  { name: "machine_env_set", input: { name: "SMOKE_DENIED", description: "Denied token", secret: true } },
  { name: "machine_upsert", input: { id: "box", label: "Smoke sshd", ssh: { host: "127.0.0.1", port: sshd.port, user: sshd.user, auth: "key", identityFile: sshd.clientKey, options: { UserKnownHostsFile: path.join(base, "known_hosts") } } } },
  { name: "shell", input: { description: "Use env vars and ssh", command: 'echo "local=$SMOKE_PLAIN secret=$SMOKE_SECRET denied=[$SMOKE_DENIED]"; ssh -F "$OCM_SSH_CONFIG" box "echo remote-$SMOKE_PLAIN-\\$(id -un)"' } },
  { name: "shell", input: { description: "Plain command", command: "env | grep -E '^(SMOKE_|OCM_|SSH_ASKPASS)' | cut -d= -f1 > plain-env.txt; echo plain-done" } },
  { name: "machine_test", input: { id: "box" } },
]
const toolResults = []
const descriptions = []
let modelRequests = 0
const server = createServer(async (req, res) => {
  const chunks = []
  for await (const part of req) chunks.push(part)
  let body
  try { body = JSON.parse(Buffer.concat(chunks).toString()) } catch { res.writeHead(400); res.end(); return }
  const main = Array.isArray(body.tools) && body.tools.some(tool => tool.function?.name === "machine_list")
  if (main) {
    modelRequests++
    descriptions.push(body.tools.find(tool => tool.function?.name === "machine_list").function.description)
    toolResults.length = 0
    for (const message of body.messages ?? []) if (message.role === "tool") toolResults.push(typeof message.content === "string" ? message.content : JSON.stringify(message.content))
  }
  const call = main ? calls.shift() : undefined
  if (!body.stream) {
    res.writeHead(200, { "content-type": "application/json" })
    res.end(JSON.stringify({ id: "x", object: "chat.completion", model: "probe", choices: [{ index: 0, message: { role: "assistant", content: "Smoke" }, finish_reason: "stop" }], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } }))
    return
  }
  const chunk = (delta, finish_reason = null) => ({ id: `c${modelRequests}`, object: "chat.completion.chunk", created: 0, model: "probe", choices: [{ index: 0, delta, finish_reason }] })
  const events = call
    ? [chunk({ role: "assistant", tool_calls: [{ index: 0, id: `call-${modelRequests}`, type: "function", function: { name: call.name, arguments: JSON.stringify(call.input) } }] }), chunk({}, "tool_calls")]
    : [chunk({ role: "assistant", content: main ? "OC_MACHINE_SMOKE_COMPLETE" : "Smoke" }), chunk({}, "stop")]
  res.writeHead(200, { "content-type": "text/event-stream" })
  res.end(events.map(value => `data: ${JSON.stringify(value)}\n\n`).join("") + "data: [DONE]\n\n")
})
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve))

await writeFile(path.join(home, "config", "opencode", "opencode.json"), JSON.stringify({
  $schema: "https://opencode.ai/config.json", model: "probe/probe",
  plugins: [pluginPath],
  providers: { probe: {
    package: "@opencode/ai/providers/openai-compatible",
    settings: { baseURL: `http://127.0.0.1:${server.address().port}/v1`, apiKey: "synthetic-not-a-secret" },
    models: { probe: { limit: { context: 32000, output: 1024 }, capabilities: { tools: true, input: ["text"], output: ["text"] } } },
  } },
}))
const env = {
  HOME: home, TMPDIR: home, PATH: [path.join(root, ".pixi/envs/default/bin"), "/usr/bin", "/bin"].join(":"),
  XDG_CONFIG_HOME: path.join(home, "config"), XDG_DATA_HOME: path.join(home, "data"),
  XDG_CACHE_HOME: path.join(home, "cache"), XDG_STATE_HOME: path.join(home, "state"),
  OPENCODE_DISABLE_CLAUDE_CODE: "true",
}
let stdout = "", stderr = ""
const child = spawn(binary, ["run", "--standalone", "--auto", "--format", "json", "--model", "probe/probe", "oc-machine smoke"], { cwd: workspace, env, detached: true, stdio: ["ignore", "pipe", "pipe"] })
child.stdout.on("data", data => { stdout += data }); child.stderr.on("data", data => { stderr += data })
const timer = setTimeout(() => { try { process.kill(-child.pid, "SIGKILL") } catch {} }, 120_000)
const code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("close", resolve) })
clearTimeout(timer); server.close(); await sshd.stop()

const logs = path.join(root, ".local", "smoke-host.log")
await writeFile(logs, `${stdout}\n----- stderr -----\n${stderr}`, { mode: 0o600 })
try {
  assert.equal(code, 0, `opencode exited ${code}; see ${logs}`)
  assert.equal(calls.length, 0, "every scripted tool call was made")
  assert.ok(stdout.includes("OC_MACHINE_SMOKE_COMPLETE"), "run completed")
  assert.doesNotMatch(stderr, /\[oc-machine\] (disabled|could not|tool reload failed)/, "no plugin warnings")

  assert.match(descriptions[0], /No machines or env vars are configured yet/)
  assert.match(descriptions.at(-1), /box \(linux, ssh\) Smoke sshd/, "inventory refreshed in the live tool list")
  assert.match(descriptions.at(-1), /SMOKE_SECRET \[secret\]: Smoke test API token/)

  const all = toolResults.join("\n")
  assert.ok(!all.includes(SECRET), "the secret never reaches the model")
  const used = toolResults.find(text => text.includes("local=plain-value"))
  assert.ok(used, "shell result reached the model")
  assert.match(used, /secret=\[REDACTED:env:SMOKE_SECRET\]/, "secret was supplied and masked in output")
  assert.match(used, /denied=\[\]/)
  assert.match(used, /\$SMOKE_DENIED: use denied by the Machines permission table/)
  assert.match(used, new RegExp(`remote-plain-value-${sshd.user}`), "ssh through the per-command config, with the key passphrase from the vault")
  assert.equal((await readFile(path.join(workspace, "plain-env.txt"), "utf8")).trim(), "", "a command that references nothing gets nothing")
  assert.ok(toolResults.some(text => text.includes('"ok": true') && text.includes(`"user": "${sshd.user}"`)), "machine_test connected")
  if (pluginPath !== root) await (await import("./install.mjs")).verifyRelease(pluginPath) // running it changed nothing
  console.log(`oc-machine host smoke passed${pluginPath !== root ? " from a snapshot" : ""} (OpenCode ${OPENCODE_VERSION}, ${process.platform}-${process.arch}, ${modelRequests} model requests).`)
  await rm(base, { recursive: true, force: true })
} catch (error) {
  console.error(`Smoke failed. Scratch home kept at ${base}; logs at ${logs}`)
  throw error
}
