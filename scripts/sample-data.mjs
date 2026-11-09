// Writes synthetic machines, env vars, secrets, permissions and a pending request into an oc-machine data directory.
// Development only (GUI checks). Usage: node --import tsx scripts/sample-data.mjs <data-dir>
import { PolicyStore, SecretRequests, Vault } from "oc-secure-kit"
import { normalizeEnvVar, normalizeMachine } from "../plugin/model.ts"
import { MachineStore } from "../plugin/store.ts"

const dir = process.argv[2]
if (!dir?.startsWith("/")) throw new Error("Usage: sample-data.mjs <absolute data dir>")
const store = await MachineStore.open(dir)
await store.put(normalizeMachine({ id: "laptop", label: "This Mac", os: "macos" }))
await store.put(normalizeMachine({ id: "bastion", label: "Jump host", ssh: { host: "bastion.example.com", user: "ops", auth: "agent" } }))
await store.put(normalizeMachine({ id: "gpu-1", label: "A100 training box", ssh: { host: "10.0.0.11", user: "me", proxyJump: "bastion", auth: "key", identityFile: "~/.ssh/id_ed25519", forwardX11: true, localForwards: ["8888:localhost:8888"] } }))
await store.put(normalizeMachine({ id: "gpu-2", label: "Second A100", ssh: { host: "10.0.0.12", user: "me", proxyJump: "bastion", auth: "password" } }))
await store.setLocal("laptop")
await store.putEnv(normalizeEnvVar({ name: "HF_TOKEN", description: "Hugging Face read token for model downloads", secret: true }))
await store.putEnv(normalizeEnvVar({ name: "WANDB_API_KEY", description: "Weights & Biases logging", secret: true }))
await store.putEnv(normalizeEnvVar({ name: "AWS_PROFILE", description: "Work AWS profile name", value: "work" }))
const vault = await Vault.open({ dir, plugin: "oc-machine" })
await vault.set("env:HF_TOKEN", "value", "hf_sample_not_real_123")
await vault.set("laptop", "sudo", "sample-sudo")
const policy = await PolicyStore.open(dir)
await policy.setCells([
  { entity: "gpu-2", row: { agent: "*" }, capability: "sudo", effect: "deny" },
  { entity: "gpu-1", row: { agent: "plan" }, capability: "ssh", effect: "ask" },
  { entity: "env:WANDB_API_KEY", row: { agent: "*" }, capability: "use", effect: "ask" },
])
await (await SecretRequests.open(dir)).add({ entity: "gpu-2", name: "ssh-password", purpose: "first login to set up a dedicated key" })
console.log(`Sample data written to ${dir}`)
