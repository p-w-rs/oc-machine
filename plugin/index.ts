import { Plugin } from "@opencode/plugin"
import { SECURE_KIT_VERSION } from "oc-secure-kit"

export const PLUGIN_ID = "oc-machine"

export function createPlugin(): Plugin.Plugin {
  return Plugin.define({
    id: PLUGIN_ID,
    async setup() {
      // Milestone 0: loads cleanly and registers nothing. Tools, hooks and RPC arrive in later milestones.
      return () => {}
    },
  })
}

export { SECURE_KIT_VERSION }
export default createPlugin()
