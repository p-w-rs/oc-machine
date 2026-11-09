import { test } from "node:test"
import assert from "node:assert/strict"
import { capabilities, defaultEffect, isFillableSlot, mergeMachine, normalizeMachine, secretSlots } from "./model.js"

const base = { id: "web-1", os: "linux", ssh: { host: "web1.example.com", user: "deploy", auth: "agent" }, env: [] }

test("normalizes a machine and fills defaults", () => {
  const machine = normalizeMachine({ id: "box", env: [{ name: "REGION", value: "us-east-1" }] }, new Date(0))
  assert.deepEqual(machine, { id: "box", os: "linux", env: [{ name: "REGION", secret: false, value: "us-east-1" }], updatedAt: "1970-01-01T00:00:00.000Z" })
})

test("accepts the full ssh feature set", () => {
  const machine = normalizeMachine({
    ...base,
    ssh: {
      host: "10.0.0.5", user: "me", port: 2222, proxyJump: "bastion,ops@jump.example:22", auth: "key", identityFile: "~/.ssh/id_ed25519",
      forwardX11: true, forwardX11Trusted: false, forwardAgent: true, localForwards: ["8080:localhost:80", "127.0.0.1:5432 db:5432"],
      remoteForwards: ["9000:localhost:9000"], serverAliveInterval: 30, options: { Compression: "yes" },
    },
  })
  assert.deepEqual(machine.ssh?.localForwards, ["8080:localhost:80", "127.0.0.1:5432:db:5432"])
  assert.equal(machine.ssh?.port, 2222)
})

test("rejects bad input with actionable messages", () => {
  const bad: [unknown, RegExp][] = [
    [{ ...base, id: "has space" }, /Invalid machine name/],
    [{ ...base, ssh: { host: "bad host;rm" } }, /not a hostname/],
    [{ ...base, ssh: { host: "h", user: "a b" } }, /valid user/],
    [{ ...base, ssh: { host: "h", auth: "key" } }, /identityFile is required/],
    [{ ...base, ssh: { host: "h", identityFile: "~/k" } }, /only applies to key auth/],
    [{ ...base, ssh: { host: "h", port: 70000 } }, /port number/],
    [{ ...base, ssh: { host: "h", proxyJump: "web-1" } }, /machine itself/],
    [{ ...base, ssh: { host: "h", localForwards: ["nonsense"] } }, /must look like/],
    [{ ...base, ssh: { host: "h", options: { Include: "/etc/x" } } }, /cannot set Include/],
    [{ ...base, ssh: { host: "h", options: { HostName: "x" } } }, /dedicated ssh field/],
    [{ ...base, ssh: { host: "h", options: { Compression: "yes\nHost *" } } }, /single-line/],
    [{ ...base, ssh: { host: "h", hostname: "x" } }, /Unknown ssh field/],
    [{ ...base, env: [{ name: "TOKEN", secret: true, value: "abc" }] }, /do not pass its value/],
    [{ ...base, env: [{ name: "1BAD", value: "x" }] }, /valid variable name/],
    [{ ...base, env: [{ name: "A", value: "x" }, { name: "A", value: "y" }] }, /listed twice/],
    [{ ...base, env: [{ name: "A" }] }, /needs a value/],
    [{ ...base, hostname: "oops" }, /Unknown machine field/],
  ]
  for (const [input, message] of bad) assert.throws(() => normalizeMachine(input), message, JSON.stringify(input))
})

test("merge: fields merge, null clears, env replaces, auth switch drops stale fields", () => {
  const existing = normalizeMachine({ ...base, label: "Web", ssh: { host: "h", auth: "key", identityFile: "~/k", forwardX11: true }, env: [{ name: "A", value: "1" }] })
  const merged = normalizeMachine(mergeMachine(existing, { label: null, ssh: { auth: "agent", port: 22 }, env: [{ name: "B", secret: true }] }))
  assert.equal(merged.label, undefined)
  assert.deepEqual(merged.ssh, { host: "h", auth: "agent", port: 22, forwardX11: true })
  assert.deepEqual(merged.env, [{ name: "B", secret: true }])
  assert.equal(normalizeMachine(mergeMachine(existing, { ssh: null })).ssh, undefined)
})

test("secret slots and capabilities follow the configuration", () => {
  const machine = normalizeMachine({ ...base, ssh: { host: "h", auth: "password" }, env: [{ name: "TOKEN", secret: true }, { name: "REGION", value: "x" }] })
  assert.deepEqual(secretSlots(machine), ["sudo", "ssh-password", "env:TOKEN"])
  assert.deepEqual(capabilities(machine), ["ssh", "sudo", "x11", "agent-forward", "manage", "remove", "env.TOKEN", "env.REGION"])
  assert.equal(isFillableSlot(machine, "env:TOKEN"), true)
  assert.equal(isFillableSlot(machine, "env:REGION"), false)
  assert.equal(isFillableSlot(machine, "key-passphrase"), false)
  const generated = normalizeMachine({ ...base, ssh: { host: "h", auth: "generated" } })
  assert.equal(isFillableSlot(generated, "ssh-key"), false, "generated keys are never typed in")
})

test("defaults favor working over prompting", () => {
  assert.equal(defaultEffect("ssh"), "allow")
  assert.equal(defaultEffect("env.TOKEN"), "allow")
  assert.equal(defaultEffect("manage"), "allow")
  assert.equal(defaultEffect("sudo"), "ask")
  assert.equal(defaultEffect("remove"), "ask")
})
