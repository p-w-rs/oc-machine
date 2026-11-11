import { test } from "node:test"
import assert from "node:assert/strict"
import { normalizeMachine, type Machine } from "./model.js"
import { renderConfig, validateConfig, type SshPolicy } from "./sshconfig.js"

const open: SshPolicy = { ssh: true, x11: true, agentForward: true }
const machines: Machine[] = [
  normalizeMachine({ id: "bastion", ssh: { host: "bastion.example.com", user: "ops", auth: "agent", identityAgent: "~/Library/Containers/x/agent.sock" } }),
  normalizeMachine({
    id: "gpu", label: "GPU box #1", ssh: {
      host: "10.1.2.3", user: "me", port: 2222, proxyJump: "bastion", auth: "key", identityFile: "~/.ssh/id ed25519",
      forwardX11: true, forwardX11Trusted: true, forwardAgent: true, localForwards: ["8888:localhost:8888", "127.0.0.1:6006:localhost:6006"],
      serverAliveInterval: 30, options: { Compression: "yes" },
    },
  }),
  normalizeMachine({ id: "legacy", ssh: { host: "old.example.com", auth: "password" } }),
  normalizeMachine({ id: "gen", ssh: { host: "gen.example.com", auth: "generated" } }),
  normalizeMachine({ id: "laptop" }),
]

test("renders a config that ssh -G accepts with the intended options", async () => {
  const text = renderConfig(machines, { keysDir: "/data/oc-machine/keys", policy: () => open })
  assert.doesNotMatch(text, /Host laptop/, "machines without ssh get no block")
  const resolved = await validateConfig(text, ["bastion", "gpu", "legacy", "gen"])
  const gpu = resolved.get("gpu")!
  assert.deepEqual(gpu.get("hostname"), ["10.1.2.3"])
  assert.deepEqual(gpu.get("user"), ["me"])
  assert.deepEqual(gpu.get("port"), ["2222"])
  assert.deepEqual(gpu.get("proxyjump"), ["bastion"])
  assert.deepEqual(gpu.get("forwardx11"), ["yes"])
  assert.deepEqual(gpu.get("forwardx11trusted"), ["yes"])
  assert.deepEqual(gpu.get("forwardagent"), ["yes"])
  assert.deepEqual(gpu.get("identitiesonly"), ["yes"])
  assert.ok(gpu.get("identityfile")!.some(path => path.endsWith("/.ssh/id ed25519")), "quoted path with a space survives")
  assert.deepEqual(gpu.get("localforward"), ["8888 [localhost]:8888", "[127.0.0.1]:6006 [localhost]:6006"])
  assert.deepEqual(gpu.get("serveraliveinterval"), ["30"])
  assert.deepEqual(gpu.get("compression"), ["yes"])
  assert.match(resolved.get("legacy")!.get("preferredauthentications")![0]!, /keyboard-interactive,password/)
  assert.deepEqual(resolved.get("legacy")!.get("pubkeyauthentication"), ["false"])
  assert.ok(resolved.get("gen")!.get("identityfile")!.includes("/data/oc-machine/keys/gen"))
  assert.ok(resolved.get("bastion")!.get("identityagent")![0]!.endsWith("/Library/Containers/x/agent.sock"))
})

test("the any-agent row removes hosts and forwarding from the shell's config", async () => {
  const policy = (id: string): SshPolicy => id === "legacy" ? { ...open, ssh: false } : { ssh: true, x11: false, agentForward: false }
  const text = renderConfig(machines, { keysDir: "/k", policy })
  assert.doesNotMatch(text, /Host legacy/)
  const gpu = (await validateConfig(text, ["gpu"])).get("gpu")!
  assert.deepEqual(gpu.get("forwardx11"), ["no"])
  assert.deepEqual(gpu.get("forwardagent"), ["no"])
  assert.equal(gpu.get("forwardx11trusted")?.[0], "no", "trusted is not emitted, so ssh's default (no) applies")
})

test("a machine that jumps through a denied host is skipped, others still render", async () => {
  const policy = (id: string): SshPolicy => id === "bastion" ? { ...open, ssh: false } : open
  const text = renderConfig(machines, { keysDir: "/k", policy })
  assert.match(text, /# gpu skipped: gpu jumps through bastion, which has no ssh access/)
  assert.match(text, /Host legacy/)
  await validateConfig(text, ["legacy"])
})

test("validateConfig reports ssh's own error", async () => {
  await assert.rejects(validateConfig("Host x\n  NoSuchOption yes\n", ["x"]), /ssh rejected the generated config for x/)
})

test("routes: preferred addresses tried first with a 1 s probe, optional network gate, one host key; reachability hint", async () => {
  const { renderConfig, validateConfig, unreachableHint } = await import("./sshconfig.js")
  const { normalizeMachine } = await import("./model.js")
  const lab = normalizeMachine({ id: "lab", ssh: { host: "ssh.example.org", port: 49222, user: "me", auth: "agent", routes: [{ host: "192.0.2.80", network: "192.0.2.0/24" }] } })
  const work = normalizeMachine({ id: "gpu-2", ssh: { host: "10.10.245.250", auth: "agent", reachability: "office Wi-Fi or work VPN" } })
  const text = renderConfig([lab, work], { keysDir: "/k", policy: () => ({ ssh: true, x11: false, agentForward: false }) })
  assert.match(text, /Match originalhost lab localnetwork 192\.0\.2\.0\/24 exec "if command -v nc[^"]*192\.0\.2\.80 22[^"]*"\n  HostName 192\.0\.2\.80\n  Port 22\nHost lab\n/)
  assert.match(text, /HostKeyAlias lab/)
  assert.match(text, /ConnectTimeout 10/)
  assert.match(text, /# gpu-2 \(reachable from: office Wi-Fi or work VPN\)/)
  const resolved = await validateConfig(text, ["lab", "gpu-2"])
  // The probe to 192.0.2.80 (TEST-NET-1, never routed) fails here (or we're not on that network), so the public route resolves.
  assert.equal(resolved.get("lab")!.get("hostname")![0], "ssh.example.org")
  assert.equal(resolved.get("lab")!.get("port")![0], "49222")
  assert.equal(resolved.get("lab")!.get("hostkeyalias")![0], "lab")
  assert.match(unreachableHint("ssh: connect to host 10.10.245.250 port 22: Operation timed out", work)!, /only reachable from: office Wi-Fi or work VPN/)
  assert.equal(unreachableHint("Permission denied (publickey)", work), undefined)
  assert.throws(() => normalizeMachine({ id: "x", ssh: { host: "h", routes: [{ host: "a", network: "home" }] } }), /CIDR/)
  // A route that answers wins: a local listener on 127.0.0.1.
  const net = await import("node:net")
  const server = net.createServer().listen(0, "127.0.0.1")
  await new Promise(resolve => server.once("listening", resolve))
  const port = (server.address() as { port: number }).port
  const near = normalizeMachine({ id: "near", ssh: { host: "far.example.org", auth: "agent", routes: [{ host: "127.0.0.1", port }] } })
  const live = await validateConfig(renderConfig([near], { keysDir: "/k", policy: () => ({ ssh: true, x11: false, agentForward: false }) }), ["near"])
  server.close()
  assert.equal(live.get("near")!.get("hostname")![0], "127.0.0.1")
  assert.equal(live.get("near")!.get("port")![0], String(port))
})
