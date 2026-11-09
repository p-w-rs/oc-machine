import { after, test } from "node:test"
import assert from "node:assert/strict"
import { mkdtemp, rm } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { PermissionBridge, StaleRevisionError } from "oc-secure-kit"
import { createAdmin } from "./admin.js"
import { defaultEffect, normalizeEnvVar, normalizeMachine } from "./model.js"
import { inherited } from "./rpc.js"
import { MachineService, PLUGIN_ID } from "./service.js"

const dirs: string[] = []
after(async () => { await Promise.all(dirs.map(dir => rm(dir, { recursive: true, force: true }))) })
const cost = { N: 2 ** 12, r: 8, p: 1 }
const PASS = "export passphrase 123"

async function setup() {
  const dir = await mkdtemp(join(tmpdir(), "ocm-admin-"))
  dirs.push(dir)
  const service = await MachineService.open(dir)
  const root = async (id: string) => id === "child" ? "root" : id
  service.attach(new PermissionBridge({ plugin: PLUGIN_ID, policy: service.policy, fallback: defaultEffect, root }))
  const admin = createAdmin({ service, root, cost, agents: async () => [{ id: "build", name: "build", mode: "primary" }] })
  return { dir, service, admin }
}

async function populate(service: MachineService) {
  await service.store.put(normalizeMachine({ id: "gpu", label: "A100", ssh: { host: "10.0.0.2", auth: "password", forwardX11: true } }))
  await service.store.put(normalizeMachine({ id: "laptop", os: "macos" }))
  await service.store.setLocal("laptop")
  await service.store.putEnv(normalizeEnvVar({ name: "HF_TOKEN", description: "Hugging Face token", secret: true }))
  await service.store.putEnv(normalizeEnvVar({ name: "REGION", description: "AWS region", value: "us-east-1" }))
}

test("state shows everything the GUI needs and never secret values", async () => {
  const { service, admin } = await setup()
  await populate(service)
  await service.vault.set("env:HF_TOKEN", "value", "hf-secret-value-1")
  await service.requests.add({ entity: "gpu", name: "ssh-password", purpose: "first login" })
  const state = await admin.state({ sessionID: "child" })
  assert.doesNotMatch(JSON.stringify(state), /hf-secret-value-1/)
  assert.deepEqual(state.machines.map(machine => [machine.id, machine.local, machine.ssh]), [["gpu", false, "10.0.0.2 · password"], ["laptop", true, undefined]])
  assert.deepEqual(state.machines[0]!.secrets, { sudo: "unset", "ssh-password": "unset" })
  assert.deepEqual(state.env.map(variable => [variable.name, variable.status]), [["HF_TOKEN", "set"], ["REGION", "set"]])
  assert.deepEqual(state.requests.map(request => request.label), ["ssh password for gpu"])
  assert.equal(state.session?.root, "root")
  assert.equal(state.defaults.sudo, "ask")
  assert.equal(state.defaults.use, "allow")
  const again = await admin.state({ sessionID: "child" })
  assert.equal(again.fingerprint, state.fingerprint, "stable when nothing changed")
})

test("cells: agent rows, any-agent row, session row and stale revisions", async () => {
  const { service, admin } = await setup()
  await populate(service)
  let state = await admin.state({})
  state = await admin.setCells({ expectedRevision: state.revision, changes: [
    { entity: "gpu", capability: "ssh", effect: "deny", agent: "*" },
    { entity: "env:HF_TOKEN", capability: "use", effect: "ask", agent: "build" },
  ] })
  assert.equal(inherited(state, "gpu", "ssh", "build"), "deny", "agents inherit the any-agent row")
  assert.equal(inherited(state, "env:HF_TOKEN", "use", "build"), "ask")
  assert.equal(inherited(state, "gpu", "sudo", "*"), "ask", "default")
  await assert.rejects(admin.setCells({ expectedRevision: 0, changes: [{ entity: "gpu", capability: "ssh", effect: "allow", agent: "*" }] }), StaleRevisionError)

  const withSession = await admin.setCells({ sessionID: "child", changes: [{ entity: "gpu", capability: "ssh", effect: "allow", session: true }] })
  assert.deepEqual(withSession.session?.cells, { gpu: { ssh: "allow" } })
  assert.equal((await service.policy.resolve({ entity: "gpu", capability: "ssh", sessionRoot: "root" })).effect, "allow")

  await assert.rejects(admin.setCells({ changes: [{ entity: "gpu", capability: "use", effect: "allow", agent: "*" }] }), /Unknown permission use/)
  await assert.rejects(admin.setCells({ changes: [{ entity: "nope", capability: "ssh", effect: "allow", agent: "*" }] }), /Unknown nope/)
  await assert.rejects(admin.setCells({ changes: [{ entity: "gpu", capability: "ssh", effect: "allow", session: true }] }), /session is needed/)
})

test("secret entry only accepts slots the configuration has, and clears requests", async () => {
  const { service, admin } = await setup()
  await populate(service)
  await service.requests.add({ entity: "env:HF_TOKEN", name: "value", purpose: "" })
  assert.deepEqual(await admin.setSecret({ entity: "env:HF_TOKEN", name: "value", value: "hf-new-value" }), { stored: "$HF_TOKEN", short: false })
  assert.deepEqual(await service.requests.list(), [])
  assert.equal(service.redactor.redact("x hf-new-value"), "x [REDACTED:env:HF_TOKEN]", "masking picks it up immediately")
  await admin.setSecret({ entity: "gpu", name: "ssh-password", value: "pw" })
  assert.equal((await admin.state({})).machines[0]!.secrets["ssh-password"], "set")
  await assert.rejects(admin.setSecret({ entity: "env:REGION", name: "value", value: "x" }), /not a secret/)
  await assert.rejects(admin.setSecret({ entity: "gpu", name: "ssh-key", value: "x" }), /no ssh-key secret/)
  await assert.rejects(admin.setSecret({ entity: "laptop", name: "ssh-password", value: "x" }), /no ssh-password/)
  assert.equal((await admin.unsetSecret({ entity: "gpu", name: "ssh-password" })).removed, true)
})

test("export on one install, preview and import on another", async () => {
  const a = await setup()
  await populate(a.service)
  await a.service.vault.set("env:HF_TOKEN", "value", "hf-exported-value")
  await a.service.vault.set("gpu", "ssh-password", "gpu-password")
  await a.service.policy.setCells([
    { entity: "gpu", row: { agent: "build" }, capability: "sudo", effect: "allow" },
    { entity: "gpu", row: { session: "root" }, capability: "ssh", effect: "deny" },
  ])
  const exported = await a.admin.exportBundle({ passphrase: PASS })
  assert.match(exported.name, /^oc-machine-\d{4}-\d{2}-\d{2}\.ocbundle$/)
  assert.deepEqual(exported.counts, { machines: 2, env: 2, secrets: 2 })
  assert.doesNotMatch(exported.content, /hf-exported-value|gpu-password|10\.0\.0\.2/)

  const b = await setup()
  await b.service.store.put(normalizeMachine({ id: "gpu", ssh: { host: "old.example" } }))
  await b.service.store.put(normalizeMachine({ id: "only-here" }))
  await assert.rejects(b.admin.previewImport({ content: exported.content, passphrase: "wrong passphrase" }), /Wrong passphrase/)
  const preview = await b.admin.previewImport({ content: exported.content, passphrase: PASS })
  assert.deepEqual(preview.machines, [
    { id: "gpu", status: "changed" }, { id: "laptop", status: "added" }, { id: "only-here", status: "local-only" },
  ])
  assert.equal(preview.secrets, 2)

  await b.admin.applyImport({ content: exported.content, passphrase: PASS, mode: "merge", localMachine: "only-here" })
  const state = await b.admin.state({ sessionID: "root" })
  assert.deepEqual(state.machines.map(machine => [machine.id, machine.local]), [["gpu", false], ["laptop", false], ["only-here", true]])
  assert.equal(await b.service.vault.get("env:HF_TOKEN", "value"), "hf-exported-value", "secrets re-encrypted under the new install's key")
  assert.equal(await b.service.vault.get("gpu", "ssh-password"), "gpu-password")
  assert.equal(inherited(state, "gpu", "sudo", "build"), "allow", "agent rows travel")
  assert.deepEqual(state.session?.cells, {}, "session overrides never travel")

  await b.admin.applyImport({ content: exported.content, passphrase: PASS, mode: "replace", localMachine: "laptop" })
  const replaced = await b.admin.state({})
  assert.deepEqual(replaced.machines.map(machine => [machine.id, machine.local]), [["gpu", false], ["laptop", true]])
  await assert.rejects(b.admin.applyImport({ content: exported.content, passphrase: PASS, mode: "replace", localMachine: "nope" }), /No machine nope/)
})

test("merge keeps local secrets and permissions unless the bundle brings its own", async () => {
  const a = await setup()
  await a.service.store.put(normalizeMachine({ id: "gpu", label: "new label", ssh: { host: "10.0.0.2", auth: "password" } }))
  const exported = await a.admin.exportBundle({ passphrase: PASS })

  const b = await setup()
  await b.service.store.put(normalizeMachine({ id: "gpu", ssh: { host: "10.0.0.2", auth: "password" } }))
  await b.service.vault.set("gpu", "ssh-password", "local-password")
  await b.service.policy.setCells([{ entity: "gpu", row: { agent: "plan" }, capability: "ssh", effect: "ask" }])
  await b.admin.applyImport({ content: exported.content, passphrase: PASS, mode: "merge" })
  assert.equal((await b.service.store.get("gpu"))?.label, "new label")
  assert.equal(await b.service.vault.get("gpu", "ssh-password"), "local-password")
  assert.equal((await b.service.policy.resolve({ entity: "gpu", capability: "ssh", agent: "plan" })).effect, "ask")
})

test("a bundle from another plugin or with stray secrets is rejected", async () => {
  const { encryptBundle } = await import("oc-secure-kit")
  const { admin } = await setup()
  const other = await encryptBundle({ plugin: "oc-github", schemaVersion: 1, payload: {} }, PASS, { cost })
  await assert.rejects(admin.previewImport({ content: other, passphrase: PASS }), /exported by oc-github/)
  const stray = await encryptBundle({ plugin: PLUGIN_ID, schemaVersion: 1, payload: { machines: {}, env: {}, permissions: {}, secrets: [{ entity: "ghost", name: "sudo", value: "x" }] } }, PASS, { cost })
  await assert.rejects(admin.previewImport({ content: stray, passphrase: PASS }), /unexpected secret for ghost/)
})
