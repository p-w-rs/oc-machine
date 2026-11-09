import { after, test } from "node:test"
import assert from "node:assert/strict"
import { mkdtemp, readFile, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import type { Plugin } from "@opencode/plugin"
import { PolicyStore, SecretRequests, Vault } from "oc-secure-kit"
import plugin, { createPlugin, parseOptions, PLUGIN_ID, SECURE_KIT_VERSION } from "./index.js"

const dirs: string[] = []
after(async () => { await Promise.all(dirs.map(dir => rm(dir, { recursive: true, force: true }))) })

type Effect = "allow" | "ask" | "deny"
type Tool = { name: string; execute: (input: unknown, context: unknown) => Promise<{ content: string }> }

/** A minimal OpenCode 2.2.6 host: permission evaluation order, tool registry, tool and shell hooks. */
async function host(options: Record<string, unknown> = {}, reply: "approve" | "reject" = "approve") {
  const dir = await mkdtemp(join(tmpdir(), "oc-machine-"))
  dirs.push(dir)
  const evaluate: ((event: any) => Promise<void> | void)[] = []
  const after: ((event: any) => Promise<void> | void)[] = []
  const shell: ((event: any) => Promise<void> | void)[] = []
  const tools = new Map<string, Tool>()
  const prompts: { action: string; resources: string[] }[] = []
  const registration = (list: unknown[], item: unknown) => { list.push(item); return { dispose: async () => { list.splice(list.indexOf(item), 1) } } }
  const ctx = {
    options: { dataDirectory: dir, ...options },
    session: { get: async ({ sessionID }: { sessionID: string }) => ({ parentID: sessionID === "child" ? "root" : undefined }) },
    permission: {
      hook: async (_: string, callback: any) => registration(evaluate, callback),
      assert: async (input: any) => {
        const event = { ...input, effect: "allow" as Effect }
        for (const hook of evaluate) await hook(event)
        if (event.effect === "deny") throw new Error(event.message ?? "denied")
        if (event.effect === "ask") { prompts.push({ action: input.action, resources: input.resources }); if (reply === "reject") throw new Error("rejected by user") }
      },
    },
    tool: {
      transform: async (callback: any) => {
        const added: string[] = []
        callback({ add: (tool: Tool) => { tools.set(tool.name, tool); added.push(tool.name) } })
        return { dispose: async () => { for (const name of added) tools.delete(name) } }
      },
      hook: async (_: string, callback: any) => registration(after, callback),
    },
    shell: { hook: async (_: string, callback: any) => registration(shell, callback) },
  }
  const cleanup = await createPlugin().setup(ctx as unknown as Plugin.Context) as () => Promise<void>
  const call = async (name: string, input: unknown, agent = "build", sessionID = "child") => {
    const tool = tools.get(name)
    if (!tool) throw new Error(`tool ${name} not registered`)
    const context = { sessionID, agent, messageID: "msg", id: "call", signal: new AbortController().signal, progress: async () => {} }
    let result: any
    try { result = { status: "completed", result: await tool.execute(input, context) } }
    catch (error) { result = { status: "error", error } }
    const event = { tool: name, ...result }
    for (const hook of after) await hook(event)
    if (event.status === "error") throw event.error
    return JSON.parse(event.result.content)
  }
  const newShell = async (env: Record<string, string | undefined> = {}) => {
    const event = { command: "true", cwd: "/", timeout: 1, shell: "/bin/sh", env: { ...env } }
    for (const hook of shell) await hook(event)
    return event.env
  }
  const runAfter = async (event: any) => { for (const hook of after) await hook(event); return event }
  return { dir, ctx, tools, prompts, call, newShell, runAfter, cleanup, hooks: { evaluate, after, shell } }
}

test("plugin identity and vendored secure-kit", async () => {
  assert.equal(plugin.id, PLUGIN_ID)
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"))
  assert.equal(pkg.dependencies["oc-secure-kit"], `file:vendor/oc-secure-kit-${SECURE_KIT_VERSION}.tgz`)
})

test("registers tools and hooks; cleanup removes them all", async () => {
  const h = await host()
  assert.deepEqual([...h.tools.keys()].sort(), ["machine_get", "machine_list", "machine_remove", "machine_request_secret", "machine_ssh_config", "machine_upsert"])
  assert.equal(h.hooks.evaluate.length, 1, "only the permission bridge; no native file guard by default")
  await h.cleanup()
  assert.equal(h.tools.size, 0)
  assert.equal(h.hooks.evaluate.length + h.hooks.after.length + h.hooks.shell.length, 0)
})

test("bad configuration disables the plugin without throwing into OpenCode", async () => {
  const h = await host({ dataDirectory: "relative/path" })
  assert.equal(h.tools.size, 0)
  assert.equal(h.hooks.shell.length, 0)
  await h.cleanup()
  assert.throws(() => parseOptions({ redactAllTools: "yes" }), /true or false/)
})

test("the agent sets up a machine end to end", async () => {
  const h = await host()
  const created = await h.call("machine_upsert", {
    id: "gpu", label: "GPU box", ssh: { host: "10.0.0.7", user: "me", auth: "password", forwardX11: true, localForwards: ["8888:localhost:8888"] },
    env: [{ name: "HF_TOKEN", secret: true }, { name: "CUDA_VISIBLE_DEVICES", value: "0" }],
  })
  assert.equal(created.saved.id, "gpu")
  assert.match(created.next, /ssh-password, env:HF_TOKEN/)
  assert.deepEqual(h.prompts, [], "creating a machine needs no approval by default")

  const config = await readFile(join(h.dir, "ssh_config"), "utf8")
  assert.match(config, /Host gpu\n {2}HostName 10\.0\.0\.7\n {2}User me/)
  assert.match(config, /ForwardX11 yes/)

  const listed = await h.call("machine_list", {})
  assert.deepEqual(listed.machines[0].secrets, { sudo: "unset", "ssh-password": "unset", "env:HF_TOKEN": "unset" })

  const got = await h.call("machine_get", { id: "gpu" })
  assert.equal(got.permissions.ssh, "allow")
  assert.equal(got.permissions.sudo, "ask")
  assert.equal(got.permissions["env.HF_TOKEN"], "allow")
  assert.equal(got.ssh, 'ssh -F "$OCM_SSH_CONFIG" gpu')

  const requested = await h.call("machine_request_secret", { id: "gpu", slot: "env:HF_TOKEN", purpose: "download weights" })
  assert.equal(requested.status, "unset")
  assert.equal((await (await SecretRequests.open(h.dir)).list())[0]!.purpose, "download weights")
  await assert.rejects(h.call("machine_request_secret", { id: "gpu", slot: "env:CUDA_VISIBLE_DEVICES" }), /not a secret of gpu/)

  const block = await h.call("machine_ssh_config", { id: "gpu" })
  assert.match(block.config, /^# GPU box\nHost gpu/)
})

test("invalid ssh settings are rejected before anything is saved", async () => {
  const h = await host()
  await assert.rejects(h.call("machine_upsert", { id: "x", ssh: { host: "h", options: { NoSuchOption: "1" } } }), /ssh rejected/)
  assert.deepEqual((await h.call("machine_list", {})).machines, [])
})

test("local machine env vars are added to new shells, additively", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "laptop", local: true, env: [{ name: "GH_TOKEN", secret: true }, { name: "AWS_PROFILE", value: "work" }] })
  await (await Vault.open({ dir: h.dir, plugin: PLUGIN_ID })).set("laptop", "env:GH_TOKEN", "ghp_example_token_value")

  const env = await h.newShell({ PATH: "/bin", AWS_PROFILE: "personal" })
  assert.equal(env.GH_TOKEN, "ghp_example_token_value")
  assert.equal(env.AWS_PROFILE, "personal", "existing variables are kept")
  assert.equal(env.OCM_SSH_CONFIG, join(h.dir, "ssh_config"))
  assert.equal(env.PATH, "/bin")

  // The user denies GH_TOKEN for the any-agent row: new shells stop getting it.
  await (await PolicyStore.open(h.dir)).setCells([{ entity: "laptop", row: { agent: "*" }, capability: "env.GH_TOKEN", effect: "deny" }])
  assert.equal((await h.newShell()).GH_TOKEN, undefined)
})

test("a broken data directory never breaks a shell", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "laptop", local: true, env: [{ name: "A", value: "1" }] })
  await rm(h.dir, { recursive: true, force: true })
  const { writeFile } = await import("node:fs/promises")
  await writeFile(h.dir, "not a directory")
  const env = await h.newShell({ PATH: "/bin" })
  assert.deepEqual(env, { PATH: "/bin" })
})

test("the permission table governs the plugin's actions per agent and session", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "prod", ssh: { host: "prod.example.com" } })
  const policy = await PolicyStore.open(h.dir)
  await policy.setCells([{ entity: "prod", row: { agent: "plan" }, capability: "manage", effect: "deny" }])
  await assert.rejects(h.call("machine_upsert", { id: "prod", notes: "x" }, "plan"), /Denied by the oc-machine permissions table/)
  await h.call("machine_upsert", { id: "prod", notes: "ok" }, "build")

  await policy.setCells([{ entity: "prod", row: { session: "root" }, capability: "manage", effect: "deny" }])
  await assert.rejects(h.call("machine_upsert", { id: "prod", notes: "y" }, "build", "child"), /Denied/, "session override covers subagents")
  await h.call("machine_upsert", { id: "prod", notes: "other session" }, "build", "elsewhere")

  // ssh denied for the any-agent row: the host disappears from the shell's ssh_config.
  await policy.setCells([{ entity: "prod", row: { agent: "*" }, capability: "ssh", effect: "deny" }])
  await h.newShell()
  assert.doesNotMatch(await readFile(join(h.dir, "ssh_config"), "utf8"), /Host prod/)
})

test("removal asks by default and deletes secrets and permissions", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "old", env: [{ name: "T", secret: true }] })
  const vault = await Vault.open({ dir: h.dir, plugin: PLUGIN_ID })
  await vault.set("old", "env:T", "value-123456")
  await h.call("machine_remove", { id: "old" })
  assert.deepEqual(h.prompts, [{ action: "oc-machine.remove", resources: ["old"] }])
  assert.equal(await vault.has("old", "env:T"), false)

  const rejecting = await host({}, "reject")
  await rejecting.call("machine_upsert", { id: "keep" })
  await assert.rejects(rejecting.call("machine_remove", { id: "keep" }), /rejected by user/)
  assert.equal((await rejecting.call("machine_list", {})).machines.length, 1)
})

test("rename moves secrets and permissions; dropped env vars lose their secrets", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "a", env: [{ name: "KEEP", secret: true }, { name: "DROP", secret: true }] })
  const vault = await Vault.open({ dir: h.dir, plugin: PLUGIN_ID })
  await vault.set("a", "env:KEEP", "keep-value-1")
  await vault.set("a", "env:DROP", "drop-value-1")
  await (await PolicyStore.open(h.dir)).setCells([{ entity: "a", row: { agent: "*" }, capability: "env.KEEP", effect: "deny" }])

  await h.call("machine_upsert", { id: "a", rename: "b", env: [{ name: "KEEP", secret: true }] })
  assert.equal(await vault.get("b", "env:KEEP"), "keep-value-1")
  assert.equal(await vault.has("b", "env:DROP"), false)
  assert.equal(await vault.has("a", "env:KEEP"), false)
  const got = await h.call("machine_get", { id: "b" })
  assert.equal(got.permissions["env.KEEP"], "deny")
})

test("secrets are masked in the plugin's tool output only, unless redactAllTools", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box", notes: "token is super-secret-value", env: [{ name: "T", secret: true }] })
  await (await Vault.open({ dir: h.dir, plugin: PLUGIN_ID })).set("box", "env:T", "super-secret-value")
  const got = await h.call("machine_get", { id: "box" })
  assert.equal(got.machine.notes, "token is [REDACTED:box/env:T]")
  const native = await h.runAfter({ tool: "read", status: "completed", result: { output: "super-secret-value" } })
  assert.equal(native.result.output, "super-secret-value", "native tool output is untouched by default")

  const all = await host({ redactAllTools: true })
  await all.call("machine_upsert", { id: "box", env: [{ name: "T", secret: true }] })
  await (await Vault.open({ dir: all.dir, plugin: PLUGIN_ID })).set("box", "env:T", "super-secret-value")
  const masked = await all.runAfter({ tool: "read", status: "completed", result: { output: "super-secret-value" } })
  assert.equal(masked.result.output, "[REDACTED:box/env:T]")
})

test("permission hook leaves native actions alone", async () => {
  const h = await host({ guardDataDirectory: false })
  const event = { sessionID: "s", action: "read", resources: [join(h.dir, "vault.key")], effect: "ask" as Effect }
  for (const hook of h.hooks.evaluate) await hook(event)
  assert.equal(event.effect, "ask")
  const guarded = await host({ guardDataDirectory: true })
  const blocked = { sessionID: "s", action: "read", resources: [join(guarded.dir, "vault.key")], effect: "allow" as Effect }
  for (const hook of guarded.hooks.evaluate) await hook(blocked)
  assert.equal(blocked.effect, "deny", "opt-in guard")
})
