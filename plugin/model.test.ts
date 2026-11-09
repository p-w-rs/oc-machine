import { test } from "node:test"
import assert from "node:assert/strict"
import { defaultEffect, envEntity, isFillableSlot, machineSlots, mergeEnvVar, mergeMachine, normalizeEnvVar, normalizeMachine } from "./model.js"

const base = { id: "web-1", os: "linux", ssh: { host: "web1.example.com", user: "deploy", auth: "agent" } }

test("normalizes a machine and fills defaults", () => {
  assert.deepEqual(normalizeMachine({ id: "box" }, new Date(0)), { id: "box", os: "linux", updatedAt: "1970-01-01T00:00:00.000Z" })
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
  assert.equal(machine.ssh?.forwardX11Trusted, false)
})

test("rejects bad machines with actionable messages", () => {
  const bad: [unknown, RegExp][] = [
    [{ ...base, id: "has space" }, /machine id/],
    [{ ...base, id: "a:b" }, /machine id/],
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
    [{ ...base, publicKey: "ssh-rsa AAAA" }, /ssh-ed25519/],
    [{ ...base, env: [] }, /Unknown machine field "env"/],
  ]
  for (const [input, message] of bad) assert.throws(() => normalizeMachine(input), message, JSON.stringify(input))
})

test("env vars need a description; secrets never take a value", () => {
  assert.deepEqual(normalizeEnvVar({ name: "HF_TOKEN", description: "Hugging Face read token", secret: true }, new Date(0)),
    { name: "HF_TOKEN", description: "Hugging Face read token", secret: true, updatedAt: "1970-01-01T00:00:00.000Z" })
  const bad: [unknown, RegExp][] = [
    [{ name: "HF_TOKEN", secret: true }, /needs a description/],
    [{ name: "HF_TOKEN", description: "x", secret: true, value: "abc" }, /do not pass its value/],
    [{ name: "1BAD", description: "x", value: "v" }, /valid variable name/],
    [{ name: "OCM_SSH_CONFIG", description: "x", value: "v" }, /reserved/],
    [{ name: "SUDO_ASKPASS", description: "x", value: "v" }, /reserved/],
    [{ name: "A", description: "x" }, /needs a value/],
    [{ name: "A", description: "line\nbreak", value: "v" }, /single-line/],
  ]
  for (const [input, message] of bad) assert.throws(() => normalizeEnvVar(input), message, JSON.stringify(input))
})

test("merging: fields merge, null clears, auth switch drops stale fields, secret drops value", () => {
  const existing = normalizeMachine({ ...base, label: "Web", ssh: { host: "h", auth: "key", identityFile: "~/k", forwardX11: true } })
  const merged = normalizeMachine(mergeMachine(existing, { label: null, ssh: { auth: "agent", port: 22 } }))
  assert.equal(merged.label, undefined)
  assert.deepEqual(merged.ssh, { host: "h", auth: "agent", port: 22, forwardX11: true })
  assert.equal(normalizeMachine(mergeMachine(existing, { ssh: null })).ssh, undefined)

  const plain = normalizeEnvVar({ name: "REGION", description: "AWS region", value: "us-east-1" })
  assert.equal(normalizeEnvVar(mergeEnvVar(plain, { description: "Default AWS region" })).value, "us-east-1")
  const secret = normalizeEnvVar(mergeEnvVar(plain, { secret: true }))
  assert.equal(secret.value, undefined)
})

test("secret slots follow the ssh auth", () => {
  const password = normalizeMachine({ ...base, ssh: { host: "h", auth: "password" } })
  assert.deepEqual(machineSlots(password), ["sudo", "ssh-password"])
  assert.equal(isFillableSlot(password, "ssh-password"), true)
  assert.equal(isFillableSlot(password, "key-passphrase"), false)
  const generated = normalizeMachine({ ...base, ssh: { host: "h", auth: "generated" } })
  assert.deepEqual(machineSlots(generated), ["sudo", "ssh-key"])
  assert.equal(isFillableSlot(generated, "ssh-key"), false, "generated keys are never typed in")
  assert.equal(envEntity("HF_TOKEN"), "env:HF_TOKEN")
})

test("defaults favor working over prompting", () => {
  for (const capability of ["ssh", "use", "manage", "x11", "agent-forward"]) assert.equal(defaultEffect(capability), "allow")
  assert.equal(defaultEffect("sudo"), "ask")
  assert.equal(defaultEffect("remove"), "ask")
})
