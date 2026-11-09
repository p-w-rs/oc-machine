import { Command, MenuItem, Panel, Plugin, SettingsPage, type Context, type MountedSession } from "@opencode/plugin/gui"
import { createSignal, For, onCleanup, onMount, Show, type JSX } from "solid-js"
import { inherited, MachinesRpc, type Effect, type ImportPreview, type StateView } from "./rpc.js"

type Ctx = Context
type Client = MountedSession["server"]["client"]
interface Target { client(): Client; location?(): MountedSession["location"]; sessionID?(): string | undefined }

const TAB = "machines"
const POLL_MS = 3000
const COLORS: Record<Effect, string> = { allow: "#2f9e44", ask: "#e8a317", deny: "#e03131" }
const LABELS: Record<string, string> = {
  ssh: "ssh", sudo: "sudo", x11: "X11", "agent-forward": "agent fwd", manage: "edit", remove: "remove", use: "use",
}
const DESCRIPTIONS: Record<string, string> = {
  ssh: "Connect with ssh/scp/rsync via $OCM_SSH_CONFIG", sudo: "Use the stored sudo password (sudo -A, $OCM_SUDO_PASSWORD)",
  x11: "X11 forwarding (when the machine enables it)", "agent-forward": "ssh agent forwarding (when the machine enables it)",
  manage: "Create or change the configuration", remove: "Delete it with its secrets", use: "Supply the value to commands that reference it",
}
const slotLabel = (slot: string) => ({ sudo: "sudo password", "ssh-password": "ssh password", "key-passphrase": "key passphrase", "ssh-key": "generated key" })[slot] ?? slot

const message = (error: unknown) => (error instanceof Error ? error.message : String(error)).replace(/^.*?Error: /, "")

/** Live state of the Machines plugin on one server, polled while shown. */
function createStore(ctx: Ctx, target: Target) {
  const [state, setState] = createSignal<StateView>()
  const [error, setError] = createSignal<string>()
  let inFlight = false
  const api = () => target.client().rpc(MachinesRpc)
  const options = () => ({ ...(target.location?.() && { location: target.location!() }) })
  const sessionInput = () => { const id = target.sessionID?.(); return id ? { sessionID: id } : {} }
  const accept = (next: unknown) => {
    const view = next as StateView
    if (view.fingerprint !== state()?.fingerprint) setState(view)
    setError(undefined)
  }
  const refresh = async () => {
    if (inFlight) return
    inFlight = true
    try { accept(await api().state(sessionInput(), options())) }
    catch (cause) { setError(message(cause)) }
    finally { inFlight = false }
  }
  /** Runs a mutation, shows its error as a toast, and refreshes. */
  const run = async <T,>(action: (rpc: ReturnType<typeof api>, opts: ReturnType<typeof options>) => Promise<T>, success?: string): Promise<T | undefined> => {
    try {
      const result = await action(api(), options())
      if (success) ctx.toast.show({ title: success, variant: "success" })
      return result
    } catch (cause) {
      const text = message(cause)
      ctx.toast.show({ title: /changed \(now revision/.test(text) ? "Permissions changed elsewhere; reloaded" : "Machines", description: /now revision/.test(text) ? undefined : text, variant: "error" })
      return undefined
    } finally { await refresh() }
  }
  onMount(() => {
    void refresh()
    const timer = setInterval(() => { if (document.visibilityState === "visible") void refresh() }, POLL_MS)
    onCleanup(() => clearInterval(timer))
  })
  return { state, error, refresh, run, sessionInput, accept }
}
type Store = ReturnType<typeof createStore>

/** One permission grid: rows are agents, columns are (entity, capability) pairs. */
function Grid(props: {
  store: Store
  columns: { entity: string; capability: string; label: string; title: string }[]
  showAll: boolean
}) {
  const state = () => props.store.state()!
  const rows = () => {
    const agents = state().agents.filter(agent => props.showAll || props.columns.some(column => state().cells[column.entity]?.[agent.id]?.[column.capability]))
    return [
      { key: "*", label: "Any agent", agent: "*" as string | undefined, title: "Default for every agent" },
      ...agents.map(agent => ({ key: agent.id, label: agent.name, agent: agent.id as string | undefined, title: `${agent.name} (${agent.mode})` })),
      ...(state().session ? [{ key: "session", label: "This session", agent: undefined, title: "Overrides for the current session and its subagents only" }] : []),
    ]
  }
  const value = (row: { agent?: string }, column: { entity: string; capability: string }) =>
    row.agent ? state().cells[column.entity]?.[row.agent]?.[column.capability] : state().session?.cells[column.entity]?.[column.capability]
  const fallback = (row: { agent?: string }, column: { entity: string; capability: string }) =>
    row.agent ? inherited(state(), column.entity, column.capability, row.agent) : undefined
  const change = (row: { agent?: string }, column: { entity: string; capability: string }, effect: Effect | null) =>
    props.store.run((rpc, opts) => rpc.setCells({
      expectedRevision: state().revision, ...props.store.sessionInput(),
      changes: [{ entity: column.entity, capability: column.capability, effect, ...(row.agent ? { agent: row.agent } : { session: true }) }],
    }, opts).then(next => props.store.accept(next)))
  const cell: JSX.CSSProperties = { padding: "4px 6px", "border-bottom": "1px solid color-mix(in srgb, currentColor 12%, transparent)", "text-align": "left", "white-space": "nowrap" }
  return (
    <div style={{ "overflow-x": "auto" }}>
      <table style={{ "border-collapse": "collapse", "font-size": "12px", width: "100%" }}>
        <thead>
          <tr>
            <th style={cell} />
            <For each={props.columns}>{column => <th style={{ ...cell, "font-weight": 500 }} title={column.title}>{column.label}</th>}</For>
          </tr>
        </thead>
        <tbody>
          <For each={rows()}>{row => (
            <tr>
              <td style={{ ...cell, opacity: 0.85, "font-style": row.agent ? undefined : "italic" }} title={row.title}>{row.label}</td>
              <For each={props.columns}>{column => {
                const own = () => value(row, column)
                const shown = () => own() ?? fallback(row, column)
                return (
                  <td style={cell}>
                    <select
                      aria-label={`${column.label} for ${row.label}`}
                      value={own() ?? ""}
                      onChange={event => void change(row, column, (event.currentTarget.value || null) as Effect | null)}
                      style={{
                        font: "inherit", background: "transparent", border: "1px solid color-mix(in srgb, currentColor 20%, transparent)", "border-radius": "4px",
                        padding: "1px 2px", color: shown() ? COLORS[shown()!] : "inherit", "font-weight": own() ? 600 : 400, opacity: own() ? 1 : 0.7,
                      }}
                    >
                      <option value="">{shown() ? `· ${shown()}` : "· inherit"}</option>
                      <option value="allow">allow</option>
                      <option value="ask">ask</option>
                      <option value="deny">deny</option>
                    </select>
                  </td>
                )
              }}</For>
            </tr>
          )}</For>
        </tbody>
      </table>
    </div>
  )
}

function SecretDialog(props: { ctx: Ctx; store: Store; entity: string; name: string; title: string; description?: string; close(): void }) {
  const [value, setValue] = createSignal("")
  const [busy, setBusy] = createSignal(false)
  const save = async () => {
    if (!value() || busy()) return
    setBusy(true)
    const result = await props.store.run((rpc, opts) => rpc.setSecret({ entity: props.entity, name: props.name, value: value() }, opts), `Saved ${props.title}`)
    setBusy(false)
    if (result) {
      setValue("")
      if ((result as { short?: boolean }).short) props.ctx.toast.show({ title: "Short secret", description: "Values under 6 characters cannot be masked in command output." })
      props.close()
    }
  }
  return (
    <props.ctx.ui.Dialog
      title={`Enter ${props.title}`}
      description={props.description ?? "Stored encrypted on this OpenCode server. The agent only sees that it is set."}
      footer={<>
        <props.ctx.ui.Button variant="ghost" onClick={() => { setValue(""); props.close() }}>Cancel</props.ctx.ui.Button>
        <props.ctx.ui.Button variant="contrast" busy={busy()} disabled={!value()} onClick={() => void save()}>Save</props.ctx.ui.Button>
      </>}
    >
      <Field label="Value"><props.ctx.ui.TextInput label={props.title} type="password" value={value()} onInput={setValue} onSubmit={() => void save()} autofocus /></Field>
    </props.ctx.ui.Dialog>
  )
}

function ExportDialog(props: { ctx: Ctx; store: Store; close(): void }) {
  const [passphrase, setPassphrase] = createSignal("")
  const [confirm, setConfirm] = createSignal("")
  const [busy, setBusy] = createSignal(false)
  const valid = () => [...passphrase()].length >= 10 && passphrase() === confirm()
  const go = async () => {
    if (!valid() || busy()) return
    setBusy(true)
    const result = await props.store.run((rpc, opts) => rpc.exportBundle({ passphrase: passphrase() }, opts)) as { name: string; content: string; counts: { machines: number; env: number; secrets: number } } | undefined
    setBusy(false)
    if (!result) return
    const saved = await props.ctx.system.save({ name: result.name, content: result.content })
    if (saved) {
      props.ctx.toast.show({ title: "Exported", description: `${result.counts.machines} machines, ${result.counts.env} env vars, ${result.counts.secrets} secrets → ${result.name}`, variant: "success" })
      props.close()
    }
  }
  return (
    <props.ctx.ui.Dialog
      title="Export machines"
      description="Machines, env vars, agent permissions and secrets in one encrypted file. Keep the passphrase; it is needed to import."
      footer={<>
        <props.ctx.ui.Button variant="ghost" onClick={props.close}>Cancel</props.ctx.ui.Button>
        <props.ctx.ui.Button variant="contrast" busy={busy()} disabled={!valid()} onClick={() => void go()}>Export…</props.ctx.ui.Button>
      </>}
    >
      <div style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
        <Field label="Passphrase (10+ characters)"><props.ctx.ui.TextInput label="Passphrase" type="password" value={passphrase()} onInput={setPassphrase} autofocus /></Field>
        <Field label="Repeat passphrase"><props.ctx.ui.TextInput label="Repeat passphrase" type="password" value={confirm()} onInput={setConfirm} invalid={!!confirm() && confirm() !== passphrase()} onSubmit={() => void go()} /></Field>
      </div>
    </props.ctx.ui.Dialog>
  )
}

function ImportDialog(props: { ctx: Ctx; store: Store; close(): void }) {
  const [content, setContent] = createSignal<string>()
  const [file, setFile] = createSignal("")
  const [passphrase, setPassphrase] = createSignal("")
  const [preview, setPreview] = createSignal<ImportPreview>()
  const [mode, setMode] = createSignal<"merge" | "replace">("merge")
  const [local, setLocal] = createSignal<string>("keep")
  const [busy, setBusy] = createSignal(false)
  let input: HTMLInputElement | undefined
  const pick = async (event: Event) => {
    const chosen = (event.currentTarget as HTMLInputElement).files?.[0]
    if (!chosen) return
    setFile(chosen.name); setPreview(undefined)
    setContent(await chosen.text())
  }
  const check = async () => {
    if (!content() || !passphrase() || busy()) return
    setBusy(true)
    setPreview(await props.store.run((rpc, opts) => rpc.previewImport({ content: content()!, passphrase: passphrase() }, opts)) as ImportPreview | undefined)
    setBusy(false)
  }
  const apply = async () => {
    if (!preview() || busy()) return
    setBusy(true)
    const result = await props.store.run((rpc, opts) => rpc.applyImport({
      content: content()!, passphrase: passphrase(), mode: mode(),
      ...(local() !== "keep" && { localMachine: local() === "none" ? null : local() }),
    }, opts), "Imported")
    setBusy(false)
    if (result) { setPassphrase(""); setContent(undefined); props.close() }
  }
  const counts = (items: readonly { status: string }[]) => {
    const by = (status: string) => items.filter(item => item.status === status).length
    return `${by("added")} new, ${by("changed")} changed, ${by("unchanged")} same${by("local-only") ? `, ${by("local-only")} only here (${mode() === "replace" ? "removed" : "kept"})` : ""}`
  }
  const machineOptions = () => [
    { value: "keep", label: "Keep current choice" }, { value: "none", label: "None" },
    ...[...new Set([...(preview()?.machines.filter(item => item.status !== "local-only" || mode() === "merge").map(item => item.id) ?? [])])].map(id => ({ value: id, label: id })),
  ]
  return (
    <props.ctx.ui.Dialog
      title="Import machines"
      description="Nothing changes until you press Import."
      size="normal"
      footer={<>
        <props.ctx.ui.Button variant="ghost" onClick={props.close}>Cancel</props.ctx.ui.Button>
        <Show when={preview()} fallback={<props.ctx.ui.Button variant="contrast" busy={busy()} disabled={!content() || !passphrase()} onClick={() => void check()}>Preview</props.ctx.ui.Button>}>
          <props.ctx.ui.Button variant={mode() === "replace" ? "danger" : "contrast"} busy={busy()} onClick={() => void apply()}>Import</props.ctx.ui.Button>
        </Show>
      </>}
    >
      <div style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
        <input ref={input} type="file" accept=".ocbundle,application/json" style={{ display: "none" }} onChange={event => void pick(event)} />
        <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
          <props.ctx.ui.Button icon="download" onClick={() => input?.click()}>Choose file…</props.ctx.ui.Button>
          <span style={{ opacity: 0.8 }}>{file() || "No file chosen"}</span>
        </div>
        <Field label="Bundle passphrase"><props.ctx.ui.TextInput label="Bundle passphrase" type="password" value={passphrase()} onInput={value => { setPassphrase(value); setPreview(undefined) }} onSubmit={() => void check()} /></Field>
        <Show when={preview()}>{view => <>
          <div style={{ "font-size": "13px", display: "flex", "flex-direction": "column", gap: "2px" }}>
            <span>Exported {new Date(view().createdAt).toLocaleString()}</span>
            <span>Machines: {counts(view().machines)}</span>
            <span>Env vars: {counts(view().env)}</span>
            <span>{view().secrets} secrets, permissions for {view().permissionEntities} items</span>
          </div>
          <Field label="Mode"><props.ctx.ui.Select label="Mode" value={mode()} onChange={setMode} options={[
            { value: "merge", label: "Merge: add and update; keep everything else" },
            { value: "replace", label: "Replace: make this install match the file" },
          ]} /></Field>
          <Field label="This computer is"><props.ctx.ui.Select label="This computer is" value={local()} onChange={setLocal} options={machineOptions()} /></Field>
        </>}</Show>
      </div>
    </props.ctx.ui.Dialog>
  )
}

/** Host inputs keep their label for screen readers only; show it too. */
function Field(props: { label: string; children: JSX.Element }) {
  return <label style={{ display: "flex", "flex-direction": "column", gap: "4px" }}><span style={muted}>{props.label}</span>{props.children}</label>
}

function Section(props: { title: string; actions?: JSX.Element; children: JSX.Element }) {
  return (
    <section style={{ display: "flex", "flex-direction": "column", gap: "8px" }}>
      <div style={{ display: "flex", "align-items": "center", gap: "8px" }}>
        <h3 style={{ margin: 0, "font-size": "13px", "font-weight": 600, flex: 1 }}>{props.title}</h3>
        {props.actions}
      </div>
      {props.children}
    </section>
  )
}

const card: JSX.CSSProperties = { border: "1px solid color-mix(in srgb, currentColor 14%, transparent)", "border-radius": "8px", padding: "10px", display: "flex", "flex-direction": "column", gap: "8px" }
const muted: JSX.CSSProperties = { opacity: 0.7, "font-size": "12px" }

/** The whole Machines view: pending requests, env vars, machines, permission grids, export/import. */
function MachinesView(props: { ctx: Ctx; target: Target }) {
  const { ctx } = props
  const store = createStore(ctx, props.target)
  const [showAll, setShowAll] = createSignal(false)
  const [envCapability, setEnvCapability] = createSignal("use")
  const openSecret = (entity: string, name: string, title: string, description?: string) =>
    ctx.dialogs.open(dialog => <SecretDialog ctx={ctx} store={store} entity={entity} name={name} title={title} description={description} close={() => dialog.close()} />)
  const clearSecret = (entity: string, name: string, title: string) =>
    store.run((rpc, opts) => rpc.unsetSecret({ entity, name }, opts), `Cleared ${title}`)
  const SecretButtons = (p: { entity: string; name: string; title: string; status: string }) => (
    <span style={{ display: "inline-flex", gap: "4px", "align-items": "center" }}>
      <span style={{ ...muted, color: p.status === "set" ? COLORS.allow : COLORS.ask }}>{p.status}</span>
      <ctx.ui.Button size="small" variant="ghost" icon="lock" onClick={() => openSecret(p.entity, p.name, p.title)}>{p.status === "set" ? "Replace" : "Set"}</ctx.ui.Button>
      <Show when={p.status === "set"}><ctx.ui.Button size="small" variant="ghost" onClick={() => void clearSecret(p.entity, p.name, p.title)}>Clear</ctx.ui.Button></Show>
    </span>
  )

  return (
    <div style={{ display: "flex", "flex-direction": "column", gap: "16px", padding: "12px", "font-size": "13px", "overflow-y": "auto", height: "100%", "box-sizing": "border-box" }}>
      <div style={{ display: "flex", gap: "6px", "align-items": "center", "flex-wrap": "wrap" }}>
        <span style={{ flex: 1, ...muted }}>Agents use these from their own shell. You own secrets and permissions.</span>
        <ctx.ui.Switch label="All agents" checked={showAll()} onChange={setShowAll} />
        <ctx.ui.Button size="small" variant="ghost" icon="download" onClick={() => ctx.dialogs.open(dialog => <ImportDialog ctx={ctx} store={store} close={() => dialog.close()} />)}>Import</ctx.ui.Button>
        <ctx.ui.Button size="small" variant="ghost" icon="cloud-upload" onClick={() => ctx.dialogs.open(dialog => <ExportDialog ctx={ctx} store={store} close={() => dialog.close()} />)}>Export</ctx.ui.Button>
        <ctx.ui.IconButton icon="refresh" label="Refresh" variant="ghost" size="small" onClick={() => void store.refresh()} />
      </div>

      <Show when={store.error() && !store.state()}>
        <div style={{ color: COLORS.deny }}>Machines unavailable: {store.error()}. Is oc-machine enabled on this server?</div>
      </Show>
      <Show when={!store.state() && !store.error()}><ctx.ui.Loader /></Show>

      <Show when={store.state()}>{state => <>
        <Show when={state().requests.length}>
          <Section title={`Requested by the agent (${state().requests.length})`}>
            <For each={state().requests}>{request => (
              <div style={{ ...card, "border-color": COLORS.ask }}>
                <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
                  <ctx.ui.Icon name="warning" />
                  <span style={{ flex: 1 }}><b>{request.label}</b>{request.purpose ? ` — ${request.purpose}` : ""}</span>
                  <ctx.ui.Button size="small" variant="contrast" icon="lock" onClick={() => openSecret(request.entity, request.name, request.label, request.purpose || undefined)}>Enter</ctx.ui.Button>
                  <ctx.ui.Button size="small" variant="ghost" onClick={() => void store.run((rpc, opts) => rpc.dismissRequest({ id: request.id }, opts))}>Dismiss</ctx.ui.Button>
                </div>
              </div>
            )}</For>
          </Section>
        </Show>

        <Section title="Env vars" actions={<>
          <span style={muted}>Permission</span>
          <select aria-label="Env var permission" value={envCapability()} onChange={event => setEnvCapability(event.currentTarget.value)} style={{ font: "inherit", "font-size": "12px", background: "transparent", color: "inherit" }}>
            <For each={state().envCapabilities}>{capability => <option value={capability}>{LABELS[capability] ?? capability}</option>}</For>
          </select>
        </>}>
          <Show when={state().env.length} fallback={<span style={muted}>None yet. Ask your agent to add one, e.g. “add HF_TOKEN for Hugging Face downloads”.</span>}>
            <div style={card}>
              <For each={state().env}>{variable => (
                <div style={{ display: "flex", gap: "8px", "align-items": "center" }}>
                  <code style={{ "font-weight": 600 }}>{variable.name}</code>
                  <span style={{ flex: 1, ...muted }}>{variable.description}</span>
                  <Show when={variable.secret} fallback={<span style={muted}>plain value</span>}>
                    <SecretButtons entity={`env:${variable.name}`} name="value" title={`$${variable.name}`} status={variable.status} />
                  </Show>
                </div>
              )}</For>
              <Grid store={store} showAll={showAll()} columns={state().env.map(variable => ({
                entity: `env:${variable.name}`, capability: envCapability(), label: variable.name, title: `${variable.description} — ${DESCRIPTIONS[envCapability()] ?? envCapability()}`,
              }))} />
            </div>
          </Show>
        </Section>

        <Section title="Machines">
          <Show when={state().machines.length} fallback={<span style={muted}>None yet. Ask your agent to set one up, e.g. “add my GPU box at 10.0.0.5, user me, key ~/.ssh/id_ed25519”.</span>}>
            <For each={[...state().machines].sort((a, b) => Number(b.local) - Number(a.local))}>{machine => (
              <div style={card}>
                <div style={{ display: "flex", gap: "8px", "align-items": "center", "flex-wrap": "wrap" }}>
                  <ctx.ui.Icon name={machine.local ? "monitor" : "server"} />
                  <b>{machine.id}</b>
                  <span style={{ flex: 1, ...muted }}>{[machine.label, machine.os, machine.ssh].filter(Boolean).join(" · ")}</span>
                  <ctx.ui.Switch label="This computer" checked={machine.local} onChange={checked => void store.run((rpc, opts) => rpc.setLocal({ id: checked ? machine.id : null }, opts))} />
                </div>
                <div style={{ display: "flex", gap: "12px", "flex-wrap": "wrap" }}>
                  <For each={Object.entries(machine.secrets)}>{([slot, status]) => (
                    <span style={{ display: "inline-flex", gap: "4px", "align-items": "center" }}>
                      <span>{slotLabel(slot)}</span>
                      <Show when={slot !== "ssh-key"} fallback={<span style={{ ...muted, color: status === "set" ? COLORS.allow : COLORS.ask }}>{status === "set" ? "created" : "missing (agent: machine_ssh_keygen)"}</span>}>
                        <SecretButtons entity={machine.id} name={slot} title={`${slotLabel(slot)} for ${machine.id}`} status={status} />
                      </Show>
                    </span>
                  )}</For>
                </div>
                <Grid store={store} showAll={showAll()} columns={state().machineCapabilities
                  .filter(capability => (capability !== "x11" || machine.forwardX11) && (capability !== "agent-forward" || machine.forwardAgent) && (machine.ssh || !["ssh", "x11", "agent-forward"].includes(capability)))
                  .map(capability => ({ entity: machine.id, capability, label: LABELS[capability] ?? capability, title: DESCRIPTIONS[capability] ?? capability }))} />
              </div>
            )}</For>
          </Show>
        </Section>
        <span style={muted}>Cells: allow runs without asking, ask shows a prompt each time, deny skips the value (the command still runs). “· x” means inherited. This session overrides apply to the current session and its subagents.</span>
      </>}</Show>
    </div>
  )
}

export default Plugin.define({
  setup(ctx) {
    const key = `${ctx.id}:${TAB}`
    const tab = { id: TAB, title: "Machines" }

    ctx.add(Panel, {
      id: "machines",
      region: "side",
      width: 640,
      mobile: { title: "Machines", order: 80, kind: "menu", icon: "server" },
      list: input => input.open.includes(TAB) ? [tab] : [],
      render: props => (
        <MachinesView ctx={ctx} target={{
          client: () => props.session.server.client,
          location: () => props.session.location,
          sessionID: () => props.session.pending ? undefined : props.session.id,
        }} />
      ),
    })

    ctx.add(MenuItem, {
      menu: "session.panel", id: "open-machines", title: "Machines", icon: "server", description: "ssh, sudo, env vars",
      run: () => { const session = ctx.sessions.current(); if (session) ctx.layout.open(key, session) },
    })

    ctx.add(Command, () => ({
      id: "open", title: "Open Machines", group: "Machines",
      slash: { name: "machines" },
      enabled: !!ctx.sessions.current(),
      run: () => { const session = ctx.sessions.current(); if (session) ctx.layout.open(key, session) },
    }))

    ctx.add(SettingsPage, {
      id: "machines",
      title: "Machines",
      icon: "server",
      entries: [{ id: "machines", title: "Machines", description: "ssh, sudo, env vars, secrets and permissions", keywords: "ssh sudo env secret token oc-machine export import" }],
      render: () => (
        <ctx.ui.SettingsLayout title="Machines" description="Machines and env vars your agents can use, their secrets, and who may use what.">
          <MachinesView ctx={ctx} target={{ client: () => ctx.client }} />
        </ctx.ui.SettingsLayout>
      ),
    })
  },
})
