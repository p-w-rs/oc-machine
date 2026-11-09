import { Plugin } from "@opencode/plugin"
import { guardDirectories, installRedaction, PermissionBridge, pluginDataDir, SECURE_KIT_VERSION, sessionRoots, type PermissionHost } from "oc-secure-kit"
import { defaultEffect } from "./model.js"
import { MachineService, PLUGIN_ID } from "./service.js"
import { createTools, TOOL_NAMES } from "./tools.js"

export { PLUGIN_ID, SECURE_KIT_VERSION }

export interface MachineOptions {
  /** Absolute path; default `$XDG_DATA_HOME/oc-machine`. */
  readonly dataDirectory?: string
  /** Also mask secrets in native tool output (read, shell, ...). Off by default: it changes native results. */
  readonly redactAllTools?: boolean
  /** Deny native file tools inside the data directory. Off by default: it changes native permissions. */
  readonly guardDataDirectory?: boolean
}

export function parseOptions(raw: unknown): MachineOptions {
  const options = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>
  const flag = (name: string) => {
    if (options[name] !== undefined && typeof options[name] !== "boolean") throw new Error(`${PLUGIN_ID}: option ${name} must be true or false`)
    return options[name] === true
  }
  if (options.dataDirectory !== undefined && typeof options.dataDirectory !== "string") throw new Error(`${PLUGIN_ID}: dataDirectory must be a string`)
  return {
    ...(options.dataDirectory !== undefined && { dataDirectory: options.dataDirectory as string }),
    redactAllTools: flag("redactAllTools"),
    guardDataDirectory: flag("guardDataDirectory"),
  }
}

const warn = (message: string, error?: unknown) =>
  console.warn(`[${PLUGIN_ID}] ${message}${error ? `: ${error instanceof Error ? error.message : String(error)}` : ""}`)

export function createPlugin(): Plugin.Plugin {
  return Plugin.define({
    id: PLUGIN_ID,
    async setup(ctx) {
      const registrations: { dispose(): Promise<void> }[] = []
      const cleanup = async () => { await Promise.allSettled(registrations.splice(0).reverse().map(item => item.dispose())) }
      try {
        const options = parseOptions(ctx.options)
        const service = await MachineService.open(pluginDataDir(PLUGIN_ID, options.dataDirectory))
        const permission = ctx.permission as unknown as PermissionHost
        const bridge = new PermissionBridge({
          plugin: PLUGIN_ID, policy: service.policy, fallback: defaultEffect,
          root: sessionRoots(async sessionID => (await ctx.session.get({ sessionID: sessionID as never })).parentID ?? undefined),
        })
        registrations.push(await bridge.install(permission))

        const tools = createTools(service, bridge)
        registrations.push(await ctx.tool.transform(editor => {
          for (const tool of tools) {
            editor.add({
              name: tool.name, description: tool.description, input: tool.input as never, options: { codemode: false },
              execute: async (input, context) => {
                try { return await tool.execute(input, context) }
                finally { await service.syncRedactor().catch(error => warn("redactor refresh failed", error)) }
              },
            })
          }
        }))
        if (options.redactAllTools) {
          // Registered before the redaction hook, so native results are masked with current secrets.
          registrations.push(await ctx.tool.hook("execute.after", async () => {
            await service.syncRedactor().catch(error => warn("redactor refresh failed", error))
          }))
        }
        registrations.push(await installRedaction(ctx.tool as never, service.redactor,
          options.redactAllTools ? "all" : new Set<string>(TOOL_NAMES), error => warn("redaction skipped", error)))

        // Additive only: never blocks or fails a shell. On any error the shell starts exactly as it would without us.
        registrations.push(await ctx.shell.hook("create.before", async event => {
          try { Object.assign(event.env, await service.shellAdditions(event.env)) }
          catch (error) { warn("shell env not added", error) }
        }))

        if (options.guardDataDirectory) registrations.push(await guardDirectories(permission, PLUGIN_ID, [service.dir]))
        await service.writeSshConfig().catch(error => warn("could not write ssh_config", error))
      } catch (error) {
        // The plugin disables itself; OpenCode and its native tools keep working.
        warn("disabled", error)
        await cleanup()
      }
      return cleanup
    },
  })
}

export default createPlugin()
