import { after, before, test } from "node:test"
import assert from "node:assert/strict"
import { spawn } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import type { Plugin } from "@opencode/plugin"
import { PolicyStore, SecretRequests, Vault } from "oc-secure-kit"
import plugin, { createPlugin, parseOptions, PLUGIN_ID, SECURE_KIT_VERSION } from "./index.js"
import { startSshd, type TestSshd } from "./testsshd.js"

const dirs: string[] = []
let sshd: TestSshd
// These tests must never change the real account's ssh files.
const REAL_SSH_FILES = ["authorized_keys", "known_hosts"].map(name => join(homedir(), ".ssh", name))
const fingerprint = async () => Promise.all(REAL_SSH_FILES.map(async path => createHash("sha256").update(await readFile(path).catch(() => Buffer.from("missing"))).digest("hex")))
let realBefore: string[]
before(async () => {
  realBefore = await fingerprint()
  // Values from the developer's own environment must not leak into tests (or test output).
  for (const name of ["HF_TOKEN", "REGION", "PROD_DB", "T", "A", "TOKEN", "API_TOKEN"]) delete process.env[name]
  sshd = await startSshd()
})
after(async () => {
  await sshd?.stop()
  await Promise.all(dirs.map(dir => rm(dir, { recursive: true, force: true })))
  assert.deepEqual(await fingerprint(), realBefore, "~/.ssh/authorized_keys and known_hosts must be unchanged")
})

type Effect = "allow" | "ask" | "deny"
type Tool = { name: string; description: string; execute: (input: unknown, context: unknown) => Promise<{ content: string }> }

/** A minimal OpenCode 2.2.6 host: permission evaluation, tool registry with reload, tool and shell hooks. */
async function host(options: Record<string, unknown> = {}, reply: "approve" | "reject" = "approve") {
  const dir = await mkdtemp(join(tmpdir(), "oc-machine-"))
  dirs.push(dir)
  const hooks = { evaluate: [] as any[], before: [] as any[], after: [] as any[], shell: [] as any[] }
  const transforms: ((editor: any) => void)[] = []
  const tools = new Map<string, Tool>()
  const prompts: { action: string; resources: string[]; metadata?: Record<string, unknown> }[] = []
  const registration = (list: unknown[], item: unknown) => { list.push(item); return { dispose: async () => { const i = list.indexOf(item); if (i >= 0) list.splice(i, 1) } } }
  const rebuild = () => { tools.clear(); for (const transform of transforms) transform({ add: (tool: Tool) => tools.set(tool.name, tool) }) }
  const ctx = {
    options: { dataDirectory: dir, ...options },
    session: { get: async ({ sessionID }: { sessionID: string }) => ({ parentID: sessionID === "child" ? "root" : undefined }) },
    permission: {
      hook: async (_: string, callback: any) => registration(hooks.evaluate, callback),
      assert: async (input: any) => {
        const event = { ...input, effect: "allow" as Effect }
        for (const hook of hooks.evaluate) await hook(event)
        if (event.effect === "deny") throw new Error(event.message ?? "denied")
        if (event.effect === "ask") {
          prompts.push({ action: input.action, resources: input.resources, metadata: input.metadata })
          if (reply === "reject") throw new Error("rejected by user")
        }
      },
    },
    tool: {
      transform: async (callback: any) => { transforms.push(callback); rebuild(); return { dispose: async () => { transforms.splice(transforms.indexOf(callback), 1); rebuild() } } },
      reload: async () => rebuild(),
      hook: async (name: string, callback: any) => registration(name === "execute.before" ? hooks.before : hooks.after, callback),
    },
    shell: { hook: async (_: string, callback: any) => registration(hooks.shell, callback) },
    agent: { list: async () => ({ data: [{ id: "build", name: "build", mode: "primary", hidden: false }, { id: "plan", name: "plan", mode: "primary", hidden: false }, { id: "title", name: "title", mode: "primary", hidden: true }] }) },
    rpc: { register: async (_: unknown, handlers: any) => { rpc = handlers; return { dispose: async () => { rpc = undefined } } } },
  }
  let rpc: any
  const cleanup = await createPlugin().setup(ctx as unknown as Plugin.Context) as () => Promise<void>
  let calls = 0
  const context = (agent: string, sessionID: string) => ({ sessionID, agent, messageID: "msg", id: `call-${++calls}`, signal: new AbortController().signal, progress: async () => {} })
  const finish = async (event: any) => {
    for (const hook of hooks.after) await hook(event)
    return event
  }

  /** Calls one of the plugin's tools like the host does. */
  const call = async (name: string, input: unknown, agent = "build", sessionID = "child") => {
    const tool = tools.get(name)
    if (!tool) throw new Error(`tool ${name} not registered`)
    const ctxt = context(agent, sessionID)
    for (const hook of hooks.before) await hook({ tool: name, ...ctxt, input })
    let event: any
    try { event = { tool: name, id: ctxt.id, input, status: "completed", result: await tool.execute(input, ctxt) } }
    catch (error) { event = { tool: name, id: ctxt.id, input, status: "error", error } }
    await finish(event)
    if (event.status === "error") throw event.error
    return JSON.parse(event.result.content)
  }

  /** Runs a command through the native shell tool path: execute.before, shell.create.before, a real sh, execute.after. */
  const shell = async (command: string, agent = "build", sessionID = "child") => {
    const ctxt = context(agent, sessionID)
    const input = { command, description: "test" }
    for (const hook of hooks.before) await hook({ tool: "shell", ...ctxt, input })
    const create = { command, cwd: dir, timeout: 60_000, shell: "/bin/sh", env: {} as Record<string, string | undefined> }
    for (const hook of hooks.shell) await hook(create)
    const { exit, output } = await new Promise<{ exit: number; output: string }>((resolve, reject) => {
      const child = spawn("/bin/sh", ["-c", command], { cwd: tmpdir(), env: { ...process.env, ...create.env } as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"] })
      let output = ""
      child.stdout.on("data", chunk => { output += chunk }); child.stderr.on("data", chunk => { output += chunk })
      child.on("error", reject)
      child.on("close", code => resolve({ exit: code ?? -1, output }))
    })
    const event = await finish({
      tool: "shell", id: ctxt.id, input, status: "completed",
      result: { output: { exit, truncated: false, output, status: "completed" }, content: [{ type: "text", text: output }], metadata: { exit } },
    })
    return { exit, text: event.result.content[0].text as string, env: create.env }
  }

  const vault = () => Vault.open({ dir, plugin: PLUGIN_ID })
  const policy = () => PolicyStore.open(dir)
  return { dir, ctx, tools, prompts, call, shell, finish, vault, policy, cleanup, hooks, rpc: () => rpc }
}

/** A machine pointing at the test sshd, with its own known_hosts so the real one is never touched. */
const sshMachine = (dir: string, extra: Record<string, unknown> = {}) => ({
  host: "127.0.0.1", port: sshd.port, user: sshd.user, auth: "key", identityFile: sshd.clientKey,
  options: { UserKnownHostsFile: join(dir, "known_hosts") }, ...extra,
})

test("plugin identity and vendored secure-kit", async () => {
  assert.equal(plugin.id, PLUGIN_ID)
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"))
  assert.equal(pkg.dependencies["oc-secure-kit"], `file:vendor/oc-secure-kit-${SECURE_KIT_VERSION}.tgz`)
})

test("registers tools and hooks; cleanup removes them all", async () => {
  const h = await host()
  assert.equal(h.tools.size, 10)
  assert.equal(h.hooks.evaluate.length, 1, "only the permission bridge; no native file guard by default")
  await h.cleanup()
  assert.equal(h.tools.size, 0)
  assert.equal(Object.values(h.hooks).reduce((sum, list) => sum + list.length, 0), 0)
})

test("the GUI RPC is registered and uses the host's visible agents", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box" })
  const state = await h.rpc().state({ sessionID: "child" })
  assert.deepEqual(state.agents.map((agent: { id: string }) => agent.id), ["build", "plan"])
  assert.equal(state.session.root, "root")
  await h.cleanup()
  assert.equal(h.rpc(), undefined)
})

test("bad configuration disables the plugin without throwing into OpenCode", async () => {
  const h = await host({ dataDirectory: "relative/path" })
  assert.equal(h.tools.size, 0)
  assert.equal(h.hooks.shell.length, 0)
  assert.throws(() => parseOptions({ redactAllTools: "yes" }), /true or false/)
})

test("commands that reference nothing run exactly as in plain OpenCode", async () => {
  const h = await host()
  await h.call("machine_env_set", { name: "HF_TOKEN", description: "Hugging Face token", value: "hf-plain-value" })
  const result = await h.shell("echo hello; ssh -V 2>/dev/null; echo done")
  assert.deepEqual(result.env, {})
  assert.equal(result.text, "hello\ndone\n")
  assert.deepEqual(h.prompts, [])
})

test("the inventory in the tool description follows configuration changes", async () => {
  const h = await host()
  assert.match(h.tools.get("machine_list")!.description, /No machines or env vars/)
  await h.call("machine_env_set", { name: "HF_TOKEN", description: "Hugging Face read token for model downloads", secret: true })
  await h.call("machine_upsert", { id: "gpu", label: "A100 box", ssh: { host: "10.0.0.9" } })
  await new Promise(resolve => setTimeout(resolve, 10))
  const description = h.tools.get("machine_list")!.description
  assert.match(description, /gpu \(linux, ssh\) A100 box/)
  assert.match(description, /HF_TOKEN \[secret\]: Hugging Face read token for model downloads/)
  assert.match(description, /ssh -F "\$OCM_SSH_CONFIG"/)
})

test("env vars are supplied by name to the one command that references them", async () => {
  const h = await host()
  await h.call("machine_env_set", { name: "HF_TOKEN", description: "Hugging Face token", secret: true })
  await h.call("machine_env_set", { name: "REGION", description: "Default region", value: "us-east-1" })

  const missing = await h.shell('echo "token=[$HF_TOKEN]"')
  assert.match(missing.text, /token=\[\]/)
  assert.match(missing.text, /\[oc-machine\] \$HF_TOKEN has no value yet/)

  await (await h.vault()).set("env:HF_TOKEN", "value", "hf_secret_value_123")
  const used = await h.shell('test "$HF_TOKEN" = hf_secret_value_123 && echo ok-$REGION; echo "$HF_TOKEN"')
  assert.equal(used.text, "ok-us-east-1\n[REDACTED:env:HF_TOKEN]\n", "value works, output is masked")
  assert.deepEqual(Object.keys(used.env).sort(), ["HF_TOKEN", "REGION"])
  assert.deepEqual(h.prompts, [], "use is allowed by default")

  const unrelated = await h.shell("echo $HOME > /dev/null; echo fine")
  assert.deepEqual(unrelated.env, {}, "nothing leaks into other commands")
})

test("the table governs env vars per agent and session, with native prompts for ask", async () => {
  const h = await host()
  await h.call("machine_env_set", { name: "PROD_DB", description: "Production DB password", secret: true })
  await (await h.vault()).set("env:PROD_DB", "value", "prod-db-password")
  const policy = await h.policy()

  await h.call("machine_env_set", { name: "REGION", description: "Default region", value: "us-east-1" })
  await policy.setCells([{ entity: "env:PROD_DB", row: { agent: "*" }, capability: "use", effect: "ask" }])
  const both = await h.shell('psql "$PROD_DB" 2>/dev/null; echo "$REGION"')
  assert.deepEqual(h.prompts.map(prompt => [prompt.action, prompt.resources]), [["oc-machine.use", ["env:PROD_DB"]]], "allowed vars are not shown in the prompt")
  assert.match(both.text, /us-east-1/)
  assert.match(String(h.prompts[0]!.metadata?.command), /psql/)

  await policy.setCells([{ entity: "env:PROD_DB", row: { agent: "plan" }, capability: "use", effect: "deny" }])
  const denied = await h.shell('echo "[$PROD_DB]"', "plan")
  assert.match(denied.text, /^\[\]\n/)
  assert.match(denied.text, /\$PROD_DB: use denied by the Machines permission table/)

  await policy.setCells([{ entity: "env:PROD_DB", row: { session: "root" }, capability: "use", effect: "allow" }])
  const session = await h.shell('test -n "$PROD_DB" && echo present', "build", "child")
  assert.match(session.text, /present/)

  const rejecting = await host({}, "reject")
  await rejecting.call("machine_env_set", { name: "T", description: "token", secret: true })
  await (await rejecting.vault()).set("env:T", "value", "t-value-123")
  await (await rejecting.policy()).setCells([{ entity: "env:T", row: { agent: "*" }, capability: "use", effect: "ask" }])
  const declined = await rejecting.shell('echo "[$T]"')
  assert.equal(declined.text, "[]\n[oc-machine] $T: use not granted (rejected by user).")
})

test("ssh from the native shell works with a passphrase-protected key", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box", ssh: sshMachine(h.dir) })
  await (await h.vault()).set("box", "key-passphrase", sshd.passphrase)
  const result = await h.shell('ssh -F "$OCM_SSH_CONFIG" box "echo connected-as-\\$(id -un)"')
  assert.equal(result.exit, 0, result.text)
  assert.equal(result.text.trim().split("\n").pop()!.trim(), `connected-as-${sshd.user}`)
  assert.ok(result.env.SSH_ASKPASS && result.env.SSH_ASKPASS_REQUIRE === "force")
  assert.doesNotMatch(await readFile(result.env.OCM_SSH_CONFIG!, "utf8").catch(() => ""), new RegExp(sshd.passphrase), "config never holds secrets")
})

test("env vars can be passed to a remote machine", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box", ssh: sshMachine(h.dir) })
  await (await h.vault()).set("box", "key-passphrase", sshd.passphrase)
  await h.call("machine_env_set", { name: "HF_TOKEN", description: "Hugging Face token", secret: true })
  await (await h.vault()).set("env:HF_TOKEN", "value", "hf_remote_value_456")
  const result = await h.shell('ssh -F "$OCM_SSH_CONFIG" box "HF_TOKEN=$HF_TOKEN sh -c \'test \\"\\$HF_TOKEN\\" = hf_remote_value_456 && echo remote-ok\'"')
  assert.match(result.text, /^remote-ok\r?$/m, result.text)
})

test("ssh denied for a machine leaves it out of the command's config", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box", ssh: sshMachine(h.dir) })
  await (await h.policy()).setCells([{ entity: "box", row: { agent: "*" }, capability: "ssh", effect: "deny" }])
  const result = await h.shell('ssh -F "$OCM_SSH_CONFIG" -o BatchMode=yes -o ConnectTimeout=3 box true')
  assert.notEqual(result.exit, 0)
  assert.match(result.text, /box: ssh denied by the Machines permission table/)
})

test("a plain ssh to a configured machine that fails gets a usage tip", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box-xyz", ssh: { host: "127.0.0.1", port: 1 } })
  const result = await h.shell("ssh -o BatchMode=yes -o ConnectTimeout=2 box-xyz true")
  assert.match(result.text, /\[oc-machine\] box-xyz is an oc-machine host: use ssh -F "\$OCM_SSH_CONFIG" box-xyz/)
})

test("machine_test and machine_ssh_keygen install a dedicated key and switch to it", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box", ssh: sshMachine(h.dir) })
  const failing = await h.call("machine_test", { id: "box" })
  assert.equal(failing.ok, false, "the key needs its passphrase")
  await (await h.vault()).set("box", "key-passphrase", sshd.passphrase)
  const ok = await h.call("machine_test", { id: "box" })
  assert.equal(ok.ok, true, JSON.stringify(ok))
  assert.equal(ok.user, sshd.user)

  const keygen = await h.call("machine_ssh_keygen", { id: "box" })
  assert.equal(keygen.installed, true)
  assert.equal(keygen.auth, "generated")
  assert.equal(keygen.test, "connected with the new key")
  assert.match(await readFile(sshd.authorizedKeys, "utf8"), /oc-machine:box/)
  const vault = await h.vault()
  assert.equal(await vault.has("box", "key-passphrase"), false, "the old key's passphrase is dropped")
  assert.equal(await vault.has("box", "ssh-key"), true)

  const result = await h.shell('ssh -F "$OCM_SSH_CONFIG" box "echo via-generated"')
  assert.match(result.text, /^via-generated\r?$/m)
  assert.match(await h.call("machine_ssh_config", { id: "box" }).then(r => r.config), /IdentityFile .*keys\/box/)
})

test("sudo: $OCM_SUDO_PASSWORD and sudo -A are supplied for the right machine and ask by default", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "here", local: true, os: "macos" })
  await (await h.vault()).set("here", "sudo", "local-sudo-password")
  const piped = await h.shell('test "$OCM_SUDO_PASSWORD" = local-sudo-password && echo got-it')
  assert.match(piped.text, /got-it/)
  assert.deepEqual(h.prompts.map(prompt => [prompt.action, prompt.resources]), [["oc-machine.sudo", ["here"]]])

  // sudo -A: run the helper ssh/sudo would run, instead of real sudo.
  const askpass = await h.shell('sudo_A_probe() { "$SUDO_ASKPASS"; }; true sudo -A x; sudo_A_probe')
  assert.equal(askpass.text, "[REDACTED:here/sudo]")
  const missing = await h.shell('echo "$OCM_SUDO_PASSWORD" | ssh -F "$OCM_SSH_CONFIG" nowhere true 2>/dev/null; true')
  assert.match(missing.text, /No configured machine is named/)
})

test("agent-managed setup: request secrets, rename, remove", async () => {
  const h = await host()
  const created = await h.call("machine_upsert", { id: "gpu", label: "GPU", ssh: { host: "10.0.0.7", auth: "password", forwardX11: true } })
  assert.match(created.next, /ssh password/)
  const requested = await h.call("machine_request_secret", { id: "gpu", slot: "ssh-password", purpose: "first login" })
  assert.equal(requested.status, "unset")
  await h.call("machine_env_set", { name: "TOKEN", description: "API token", secret: true })
  const envRequest = await h.call("machine_request_secret", { env: "TOKEN" })
  assert.match(envRequest.tellUser, /pixi run secret-set TOKEN/)
  assert.equal((await (await SecretRequests.open(h.dir)).list()).length, 2)
  await assert.rejects(h.call("machine_request_secret", { id: "gpu", slot: "key-passphrase" }), /no key-passphrase/)

  await (await h.vault()).set("gpu", "ssh-password", "gpu-password")
  await h.call("machine_upsert", { id: "gpu", rename: "gpu-1" })
  assert.equal(await (await h.vault()).get("gpu-1", "ssh-password"), "gpu-password")
  await h.call("machine_env_set", { name: "TOKEN", rename: "API_TOKEN" })
  assert.ok((await h.call("machine_list", {})).env.some((variable: { name: string }) => variable.name === "API_TOKEN"))

  await h.call("machine_remove", { id: "gpu-1" })
  await h.call("machine_env_remove", { name: "API_TOKEN" })
  assert.deepEqual(h.prompts.map(prompt => prompt.action), ["oc-machine.remove", "oc-machine.remove"])
  assert.deepEqual(await (await h.vault()).list(), [])
})

test("secrets are masked in the plugin's tool output; native output only for calls it supplied", async () => {
  const h = await host()
  await h.call("machine_upsert", { id: "box", notes: "token is super-secret-value" })
  await h.call("machine_env_set", { name: "T", description: "token", secret: true })
  await (await h.vault()).set("env:T", "value", "super-secret-value")
  assert.equal((await h.call("machine_get", { id: "box" })).machine.notes, "token is [REDACTED:env:T]")
  const native = await h.finish({ tool: "read", id: "x", input: {}, status: "completed", result: { output: "super-secret-value" } })
  assert.equal(native.result.output, "super-secret-value", "native output untouched by default")
  const plainShell = await h.shell("echo super-secret-value")
  assert.equal(plainShell.text, "super-secret-value\n", "shell calls the plugin did not supply are untouched")
})

test("a broken data directory never breaks a shell", async () => {
  const h = await host()
  await h.call("machine_env_set", { name: "A", description: "a", value: "1" })
  await rm(h.dir, { recursive: true, force: true })
  await writeFile(h.dir, "not a directory")
  const result = await h.shell("echo $A-still-runs")
  assert.equal(result.text, "-still-runs\n")
})

test("permission hook leaves native actions alone unless the guard is opted in", async () => {
  const h = await host()
  const event = { sessionID: "s", action: "read", resources: [join(h.dir, "vault.key")], effect: "ask" as Effect }
  for (const hook of h.hooks.evaluate) await hook(event)
  assert.equal(event.effect, "ask")
  const guarded = await host({ guardDataDirectory: true })
  const blocked = { sessionID: "s", action: "read", resources: [join(guarded.dir, "vault.key")], effect: "allow" as Effect }
  for (const hook of guarded.hooks.evaluate) await hook(blocked)
  assert.equal(blocked.effect, "deny")
})
