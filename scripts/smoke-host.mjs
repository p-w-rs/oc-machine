// End-to-end check against a real OpenCode CLI (pinned version) in an isolated home, driven by a scripted local
// model (not a real LLM). It verifies the plugin loads, its tools run, and new shells receive the env vars.
// The CLI for this platform is installed on demand into .local/host; it is not a project dependency.
import assert from "node:assert/strict"
import { spawn, spawnSync } from "node:child_process"
import { access, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises"
import { createServer } from "node:http"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { Vault } from "oc-secure-kit"

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
const SECRET = "smoke-secret-value-8c1f"

// The user stored this secret earlier (e.g. with `pixi run secret-set`); the agent only ever sees "set".
await (await Vault.open({ dir: dataDir, plugin: "oc-machine" })).set("here", "env:OCM_SMOKE_SECRET", SECRET)

const calls = [
  { name: "machine_upsert", input: { id: "here", local: true, ssh: { host: "127.0.0.1", user: "smoke", forwardX11: true }, env: [{ name: "OCM_SMOKE_PLAIN", value: "plain-value" }, { name: "OCM_SMOKE_SECRET", secret: true }] } },
  { name: "machine_get", input: { id: "here" } },
  { name: "shell", input: { description: "Read injected env", command: 'printf "%s|%s|%s\\n" "$OCM_SMOKE_PLAIN" "$OCM_SSH_CONFIG" "$OCM_SMOKE_SECRET" > shell-env.txt && ssh -G -F "$OCM_SSH_CONFIG" here | grep -E "^(hostname|user|forwardx11) " >> shell-env.txt' } },
]
const toolResults = []
let modelRequests = 0
const server = createServer(async (req, res) => {
  const chunks = []
  for await (const part of req) chunks.push(part)
  let body
  try { body = JSON.parse(Buffer.concat(chunks).toString()) } catch { res.writeHead(400); res.end(); return }
  const main = Array.isArray(body.tools) && body.tools.some(tool => tool.function?.name === "machine_upsert")
  if (main) {
    modelRequests++
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
  plugins: [root],
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
const timer = setTimeout(() => { try { process.kill(-child.pid, "SIGKILL") } catch {} }, 90_000)
const code = await new Promise((resolve, reject) => { child.on("error", reject); child.on("close", resolve) })
clearTimeout(timer); server.close()

const logs = path.join(root, ".local", "smoke-host.log")
await writeFile(logs, `${stdout}\n----- stderr -----\n${stderr}`, { mode: 0o600 })
try {
  assert.equal(code, 0, `opencode exited ${code}; see ${logs}`)
  assert.equal(calls.length, 0, "every scripted tool call was made")
  assert.ok(stdout.includes("OC_MACHINE_SMOKE_COMPLETE"), "run completed")
  const machineGet = toolResults.find(text => text.includes('"permissions"'))
  assert.ok(machineGet, "machine_get result reached the model")
  assert.match(machineGet, /"env:OCM_SMOKE_SECRET": "set"/)
  assert.ok(!toolResults.some(text => text.includes(SECRET)), "the secret never appears in a plugin tool result")
  const shellEnv = (await readFile(path.join(workspace, "shell-env.txt"), "utf8")).split("\n")
  assert.equal(shellEnv[0], `plain-value|${path.join(dataDir, "ssh_config")}|${SECRET}`, "new shells get the local machine's env vars")
  assert.ok(shellEnv.includes("hostname 127.0.0.1") && shellEnv.includes("user smoke") && shellEnv.includes("forwardx11 yes"), "ssh resolves the alias through OCM_SSH_CONFIG")
  console.log(`oc-machine host smoke passed (OpenCode ${OPENCODE_VERSION}, ${process.platform}-${process.arch}, ${modelRequests} model requests).`)
  await rm(base, { recursive: true, force: true })
} catch (error) {
  console.error(`Smoke failed. Scratch home kept at ${base}; logs at ${logs}`)
  throw error
}
