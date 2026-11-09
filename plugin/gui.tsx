import { Plugin, SettingsPage } from "@opencode/plugin/gui"

export default Plugin.define({
  setup(ctx) {
    ctx.add(SettingsPage, {
      id: "machines",
      title: "Machines",
      icon: "server",
      entries: [{ id: "machines", title: "Machines", description: "SSH, sudo, env vars and permissions per machine", keywords: "ssh sudo env oc-machine" }],
      render: () => (
        <ctx.ui.SettingsLayout title="Machines">
          <p>oc-machine is installed. Machine setup arrives in a later milestone.</p>
        </ctx.ui.SettingsLayout>
      ),
    })
  },
})
