import { after, test } from "node:test"
import assert from "node:assert/strict"
import { execFile } from "node:child_process"
import { mkdtemp, readdir, rm, stat, utimes, writeFile } from "node:fs/promises"
import { homedir, tmpdir } from "node:os"
import { join } from "node:path"
import { promisify } from "node:util"
import { RunDir, writeKey, writeSshAskpass, writeSudoAskpass } from "./rundir.js"

const exec = promisify(execFile)
const dirs: string[] = []
after(async () => { await Promise.all(dirs.map(dir => rm(dir, { recursive: true, force: true }))) })
const base = async () => { const dir = await mkdtemp(join(tmpdir(), "ocm-run-")); dirs.push(dir); return dir }
const ask = async (script: string, prompt: string) => {
  try { return (await exec(script, [prompt])).stdout } catch (error) { return `exit ${(error as { code: number }).code}` }
}

test("ssh askpass answers the right password or passphrase for each prompt", async () => {
  const run = await RunDir.create(await base())
  const script = await writeSshAskpass(run, [
    { kind: "password", match: "10.0.0.2", value: "pw-for-gpu" },
    { kind: "password", match: "jump.example.com", value: "pw-for-jump" },
    { kind: "passphrase", match: "~/.ssh/id_work", value: "key-passphrase" },
  ])
  assert.equal(await ask(script, "me@10.0.0.2's password: "), "pw-for-gpu")
  assert.equal(await ask(script, "(ops@jump.example.com) Password: "), "pw-for-jump")
  assert.equal(await ask(script, `Enter passphrase for key '${join(homedir(), ".ssh/id_work")}': `), "key-passphrase")
  assert.equal(await ask(script, "me@10.0.0.20's password: "), "exit 1", "no prefix confusion between hosts")
  assert.equal(await ask(script, "Are you sure you want to continue connecting (yes/no)?"), "exit 1")
  assert.equal((await stat(script)).mode & 0o777, 0o700)
  assert.equal((await stat(run.path)).mode & 0o777, 0o700)
})

test("a single password answers any password prompt", async () => {
  const run = await RunDir.create(await base())
  const script = await writeSshAskpass(run, [{ kind: "password", match: "host.example", value: "only-one" }])
  assert.equal(await ask(script, "Password: "), "only-one")
})

test("sudo askpass, keys and cleanup", async () => {
  const dir = await base()
  const run = await RunDir.create(dir)
  assert.equal(await ask(await writeSudoAskpass(run, "sudo-pw"), "[sudo] password for me: "), "sudo-pw")
  const key = await writeKey(run, "gpu", "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----")
  assert.equal((await stat(key)).mode & 0o777, 0o600)
  await run.remove()
  assert.deepEqual(await readdir(dir), [])

  const stale = await RunDir.create(dir)
  const fresh = await RunDir.create(dir)
  const old = new Date(Date.now() - 60 * 60_000)
  await writeFile(stale.file(".owner"), "2147483646") // left behind by a process that has exited
  await utimes(stale.path, old, old)
  await RunDir.sweep(dir)
  assert.deepEqual(await readdir(dir), [fresh.path.split("/").pop()])
})
