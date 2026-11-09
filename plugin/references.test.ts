import { test } from "node:test"
import assert from "node:assert/strict"
import { normalizeMachine } from "./model.js"
import { analyzeCommand, isEmpty } from "./references.js"

const machines = [
  normalizeMachine({ id: "gpu", ssh: { host: "10.0.0.2", proxyJump: "bastion" } }),
  normalizeMachine({ id: "gpu-2", ssh: { host: "10.0.0.3" } }),
  normalizeMachine({ id: "bastion", ssh: { host: "b.example.com" } }),
  normalizeMachine({ id: "local", os: "macos" }),
]
const input = { envNames: new Set(["HF_TOKEN", "AWS_PROFILE"]), machines, localMachine: "local" }
const analyze = (command: string) => analyzeCommand(command, input)

test("plain commands reference nothing", () => {
  for (const command of ["ls -la", "echo $HOME", "ssh gpu uptime", "cat /usr/local/gpu", "sudo apt update"]) {
    assert.equal(isEmpty(analyze(command)), true, command)
  }
})

test("finds defined env vars in both $NAME and ${NAME} forms", () => {
  assert.deepEqual(analyze('huggingface-cli download x --token "$HF_TOKEN" && echo ${AWS_PROFILE:-x} $OTHER').env, ["AWS_PROFILE", "HF_TOKEN"])
})

test("finds ssh targets and their jump hosts only with $OCM_SSH_CONFIG", () => {
  const refs = analyze('ssh -F "$OCM_SSH_CONFIG" gpu nvidia-smi')
  assert.deepEqual(refs.targets, ["gpu"])
  assert.deepEqual(refs.sshMachines.sort(), ["bastion", "gpu"])
  assert.deepEqual(analyze('scp -F "$OCM_SSH_CONFIG" model.bin me@gpu-2:/data/').targets, ["gpu-2"], "gpu-2 does not also match gpu")
  assert.deepEqual(analyze('rsync -e "ssh -F $OCM_SSH_CONFIG" ./out/ gpu-2:/srv/out/').targets, ["gpu-2"])
  assert.deepEqual(analyze('ssh -F "$OCM_SSH_CONFIG" gpu cat /opt/gpu-2/x').targets, ["gpu"], "path segments are not hosts")
  assert.deepEqual(analyze('ssh -F "${OCM_SSH_CONFIG}" local true').targets, [], "machines without ssh are ignored")
})

test("sudo password goes to the single target, else this computer", () => {
  assert.deepEqual(analyze(`printf '%s\\n' "$OCM_SUDO_PASSWORD" | ssh -F "$OCM_SSH_CONFIG" gpu "sudo -S -p '' id"`).sudoTarget, { machine: "gpu" })
  assert.deepEqual(analyze(`echo "$OCM_SUDO_PASSWORD" | sudo -S id`).sudoTarget, { machine: "local" })
  assert.match((analyze(`echo $OCM_SUDO_PASSWORD | ssh -F $OCM_SSH_CONFIG gpu x; ssh -F $OCM_SSH_CONFIG gpu-2 y`).sudoTarget as { problem: string }).problem, /ambiguous/)
  assert.match((analyzeCommand("echo $OCM_SUDO_PASSWORD", { ...input, localMachine: undefined }).sudoTarget as { problem: string }).problem, /marked local/)
})

test("detects sudo -A on this computer", () => {
  for (const command of ["sudo -A apt update", "cd x && sudo -n -A make install", "sudo --askpass id", "sudo -AE env", "(sudo -u root -A id)"]) {
    assert.equal(analyze(command).sudoAskpass, true, command)
  }
  for (const command of ["sudo apt update", "sudo -S id", "echo pseudo -A", "ls -A"]) assert.equal(analyze(command).sudoAskpass, false, command)
})
