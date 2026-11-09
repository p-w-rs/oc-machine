import { test } from "node:test"
import assert from "node:assert/strict"
import { normalizeMachine } from "./model.js"
import { SSH_CONFIG_VAR, shellAdditions } from "./shellenv.js"

const local = normalizeMachine({
  id: "me", env: [
    { name: "GH_TOKEN", secret: true },
    { name: "AWS_PROFILE", value: "work" },
    { name: "EDITOR", value: "nvim", override: true },
    { name: "DENIED", value: "x" },
    { name: "UNSET_SECRET", secret: true },
  ],
})
const input = {
  local, allowed: (name: string) => name !== "DENIED",
  secrets: new Map([["GH_TOKEN", "ghp_example_value"]]), sshConfigPath: "/data/ssh_config",
}

test("adds allowed variables and the ssh config path", () => {
  assert.deepEqual(shellAdditions(input, { PATH: "/bin" }), {
    [SSH_CONFIG_VAR]: "/data/ssh_config", GH_TOKEN: "ghp_example_value", AWS_PROFILE: "work", EDITOR: "nvim",
  })
})

test("never replaces existing variables unless marked override", () => {
  const additions = shellAdditions(input, { GH_TOKEN: "from-user-env", AWS_PROFILE: "personal", EDITOR: "vim", [SSH_CONFIG_VAR]: "/mine" })
  assert.deepEqual(additions, { EDITOR: "nvim" })
})

test("without a local machine only the ssh config path is added", () => {
  assert.deepEqual(shellAdditions({ ...input, local: undefined }, {}), { [SSH_CONFIG_VAR]: "/data/ssh_config" })
  assert.deepEqual(shellAdditions({ ...input, local: undefined, sshConfigPath: undefined }, {}), {})
})
