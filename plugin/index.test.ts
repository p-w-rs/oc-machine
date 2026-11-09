import { test } from "node:test"
import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import type { Plugin } from "@opencode/plugin"
import plugin, { createPlugin, PLUGIN_ID, SECURE_KIT_VERSION } from "./index.js"

test("defines the oc-machine server plugin", () => {
  assert.equal(plugin.id, PLUGIN_ID)
  assert.equal(typeof createPlugin().setup, "function")
})

test("setup registers nothing yet and returns a cleanup", async () => {
  const touched: string[] = []
  const context = new Proxy({}, { get: (_, key) => { touched.push(String(key)); return undefined } })
  const cleanup = await createPlugin().setup(context as Plugin.Context)
  assert.equal(typeof cleanup, "function")
  assert.deepEqual(touched, [])
})

test("vendored secure-kit is the version package.json pins", async () => {
  const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"))
  assert.equal(pkg.dependencies["oc-secure-kit"], `file:vendor/oc-secure-kit-${SECURE_KIT_VERSION}.tgz`)
})
