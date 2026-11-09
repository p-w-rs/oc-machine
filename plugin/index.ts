import { Plugin } from "@opencode/plugin"
import { guardDirectories, installRedaction, PermissionBridge, pluginDataDir, SECURE_KIT_VERSION, sessionRoots, type PermissionHost } from "oc-secure-kit"
import { createAdmin } from "./admin.js"
import { defaultEffect } from "./model.js"
import { MachinesRpc } from "./rpc.js"
import { NativeShell } from "./nativeshell.js"
import { MachineService, PLUGIN_ID } from "./service.js"
import { createTools, TOOL_NAMES } from "./tools.js"

export { PLUGIN_ID, SECURE_KIT_VERSION }

export interface MachineOptions {
  /** Absolute path; default `$XDG_DATA_HOME/oc-machine`. */
  readonly dataDirectory?: string
  /** Also mask secrets in every native tool's output (read, grep, ...). Off by default: it changes native results. */
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
      const registrations: { dispose(): Promise<void> | void }[] = []
      const cleanup = async () => { await Promise.allSettled(registrations.splice(0).reverse().map(async item => item.dispose())) }
      try {
        const options = parseOptions(ctx.options)
        const service = await MachineService.open(pluginDataDir(PLUGIN_ID, options.dataDirectory))
        const permission = ctx.permission as unknown as PermissionHost
        const root = sessionRoots(async sessionID => (await ctx.session.get({ sessionID: sessionID as never })).parentID ?? undefined)
        const bridge = new PermissionBridge({ plugin: PLUGIN_ID, policy: service.policy, fallback: defaultEffect, root })
        registrations.push(await bridge.install(permission))
        service.attach(bridge)

        // Tool descriptions carry the inventory; they are rebuilt whenever the configuration changes.
        const tools = createTools(service)
        registrations.push(await ctx.tool.transform(editor => {
          for (const tool of tools) {
            editor.add({
              name: tool.name, description: tool.description(), input: tool.input as never, options: { codemode: false },
              execute: async (input, context) => {
                try { return await tool.execute(input, context) }
                finally { await service.syncRedactor().catch(error => warn("redactor refresh failed", error)) }
              },
            })
          }
        }))
        let reloading: Promise<void> | undefined
        const unsubscribe = service.store.onChange(() => {
          reloading ??= Promise.resolve().then(() => ctx.tool.reload()).catch(error => warn("tool reload failed", error)).finally(() => { reloading = undefined })
        })
        registrations.push({ dispose: unsubscribe })

        // The plugin's own tool output is always masked; native output only when it received secrets (below).
        registrations.push(await installRedaction(ctx.tool as never, service.redactor,
          options.redactAllTools ? "all" : new Set<string>(TOOL_NAMES), error => warn("redaction skipped", error)))

        // Values for native shell commands that reference them. Commands that reference nothing are untouched.
        const shell = new NativeShell(service, warn)
        registrations.push({ dispose: () => shell.dispose() })
        registrations.push(await ctx.tool.hook("execute.before", event => shell.before(event)))
        registrations.push(await ctx.shell.hook("create.before", event => shell.create(event)))
        registrations.push(await ctx.tool.hook("execute.after", event => shell.after(event as never)))
        if (options.redactAllTools) {
          registrations.push(await ctx.tool.hook("execute.after", async () => { await service.syncRedactor().catch(() => {}) }))
        }

        // GUI only: permissions, secret entry, export/import. Never exposed as agent tools.
        const admin = createAdmin({
          service, root,
          agents: async () => ((await ctx.agent.list()).data ?? [])
            .filter(agent => !agent.hidden)
            .map(agent => ({ id: agent.id as string, name: agent.name, mode: agent.mode })),
        })
        registrations.push(await ctx.rpc.register(MachinesRpc, {
          state: async input => admin.state(input as never),
          setCells: async input => admin.setCells(input as never),
          setSecret: async input => admin.setSecret(input as never),
          unsetSecret: async input => admin.unsetSecret(input as never),
          dismissRequest: async input => admin.dismissRequest(input as never),
          setLocal: async input => admin.setLocal(input as never),
          exportBundle: async input => admin.exportBundle(input as never),
          previewImport: async input => admin.previewImport(input as never),
          applyImport: async input => admin.applyImport(input as never),
        }))

        if (options.guardDataDirectory) registrations.push(await guardDirectories(permission, PLUGIN_ID, [service.dir]))
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
