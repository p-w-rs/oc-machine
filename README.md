# oc-machine

Machines and env vars for OpenCode agents. The plugin tells the agent what
exists (machines, env vars with descriptions); the agent uses them **from its
own shell**, and the plugin supplies the values to that one command after a
permission check. macOS and Linux. Requires OpenCode 2.2.6+ and Pixi.

**Status:** machine and env var setup, ssh (agent, key + passphrase, password,
generated keys, jump hosts, forwarding), sudo, permissions, masking, the
Review-pane / Settings GUI, encrypted export/import and the installer work.

Tested on macOS (Apple Silicon, OpenCode 2.2.6 CLI and Desktop) and Ubuntu 24.04
arm64 (OpenCode 2.2.6 CLI): full test suite, real-CLI smoke tests from the
checkout and from an installed snapshot, install / rollback / uninstall, and a
bundle exported on macOS imported on Linux. Linux x86-64 and the Linux Desktop
app are not tested.

## The Machines view (you)

Open it with `/machines`, the **+** menu of the side panel, or
**Settings → Machines**. It shows:

- **Requested by the agent** — secrets the agent asked for; **Enter** opens a
  password field. Values go straight to the encrypted vault on the server.
- **Env vars** and **Machines** — what is configured, which secrets are set,
  and a permission grid per item: rows **Any agent**, agents with their own
  settings (**All agents** shows every agent), and **This session** (in the
  Review pane: the current session and its subagents). Each cell is inherit /
  allow / ask / deny; inherited values are shown faintly as `· allow`.
- **This computer** switch per machine (used for `sudo -A`).
- **Export** — one file with machines, env vars, agent permissions and secrets,
  encrypted with a passphrase you choose. **Import** previews what would be
  added, changed or kept, then **merges** (keeps local secrets and permissions
  unless the file brings its own) or **replaces**. Session overrides and the
  "This computer" choice never travel; you pick the latter on import.

**Allow always** on the native prompt sets those cells to allow in the asking
agent's row (you will see it in the table); **Allow once** changes nothing.

## How the agent uses it

The `machine_list` tool description carries a live inventory (names and
descriptions, never values), e.g.

```
Machines:
  gpu-2 (linux, ssh) A100 training box
  here (macos, this computer)
Env vars (usable on any machine):
  HF_TOKEN [secret]: Hugging Face read token for model downloads
```

The agent then just writes normal shell commands:

| In the command | Supplied for that command only |
|---|---|
| `$HF_TOKEN` (any defined env var) | its value |
| `ssh -F "$OCM_SSH_CONFIG" gpu-2 …` (also scp, rsync `-e`, sftp) | a per-command ssh config with keys, jump hosts and allowed forwarding, plus answers for password / passphrase prompts |
| `ssh -F "$OCM_SSH_CONFIG" gpu-2 "HF_TOKEN=$HF_TOKEN python x.py"` | a variable used on a remote machine |
| `printf '%s\n' "$OCM_SUDO_PASSWORD" \| ssh -F "$OCM_SSH_CONFIG" gpu-2 "sudo -S -p '' cmd"` | remote sudo password |
| `sudo -A cmd` | local sudo password (`SUDO_ASKPASS`) |

### Machines with more than one address, or only reachable from some networks

- **`ssh.routes`**: preferred addresses tried in order before `ssh.host`, e.g. a home server reached directly on
  the home LAN and through a router port forward everywhere else:
  `{ host: "ssh.example.org", port: 49222, routes: [{ host: "192.168.0.80", network: "192.168.0.0/24" }] }`.
  A route is used when its address answers within one second (and, with `network`, only while this computer is on
  that network; needs OpenSSH 9.4+). All routes share one known-hosts entry, so a different machine answering on a
  route is still rejected.
- **`ssh.reachability`**: where a private machine can be reached from, e.g. "office Wi-Fi or work VPN". It shows in
  the inventory, and when ssh cannot reach the machine the agent is told to ask you to connect instead of
  changing settings.
- Every machine gets `ConnectTimeout 10`, so an unreachable machine fails in seconds (override in `ssh.options`).

A command that references none of these runs exactly as in plain OpenCode.
A value that is denied or declined is simply not supplied; the command still
runs and its result gets a one-line `[oc-machine]` note saying why. Secret
values are masked in the output of commands they were supplied to.

## What it never changes

It never blocks or prompts for native tools on its own, never edits
`~/.ssh/config` or `authorized_keys` on this computer, never adds anything to
commands that do not reference it, and never touches native tool output
except for commands it supplied values to (masking + notes) and a usage tip
when a plain `ssh <configured-machine>` fails. If anything goes wrong inside
the plugin, it skips its own part and OpenCode carries on.

## Adding a machine

1. `machine_upsert` with `auth: "password"` (and `routes` / `reachability` if needed, see above).
2. You enter the machine's password once as its **sudo** secret (Settings → Machines). It is also used to log in;
   set a separate `ssh-password` only if the two differ.
3. `machine_ssh_keygen` creates a dedicated ed25519 key for OpenCode, installs it with that password, and switches
   the machine to it. The private key stays encrypted in the vault.
4. `machine_test`, then review the machine's row in the permission table (sudo asks by default).

## Setup tools (the agent calls these)

| Tool | |
|---|---|
| `machine_list`, `machine_get` | Inventory, which secrets are set (never values), what this agent may do |
| `machine_upsert` / `machine_remove` | Machines; `local: true` marks this computer. SSH settings are checked with `ssh -G` |
| `machine_env_set` / `machine_env_remove` | Global env vars, each with a description |
| `machine_request_secret` | Ask you for a secret env value or a machine's `sudo` / `ssh-password` / `key-passphrase` |
| `machine_ssh_keygen` | Dedicated ed25519 key per machine, installed with the current login |
| `machine_test` | Log in and report OS / user / hostname |
| `machine_ssh_config` | Show the generated config |

## Entering secrets

```sh
pixi run secret-set HF_TOKEN             # a secret env var; prompts with echo off (or pipe on stdin)
pixi run secret-set gpu-2 sudo           # sudo | ssh-password | key-passphrase
pixi run secret-unset HF_TOKEN
pixi run secret-list                     # pending requests and stored secrets, never values
```

Set `OC_MACHINE_DATA_DIR` if you configured a custom `dataDirectory`.

## Permissions

Two tables, each with a row per agent, an any-agent (`*`) row and per-session
overrides (covering subagents). Cells are allow / ask / deny; **ask** shows
OpenCode's native prompt; a native deny rule in your config still wins.

- **Machines:** `ssh`, `sudo`, `x11`, `agent-forward`, `manage`, `remove`
- **Env vars:** `use`, `manage`, `remove` per variable

Unset cells allow, except `sudo` and `remove`, which ask. Order: session
override, then the agent's row, then `*`, then the default.

## Options

```jsonc
{ "plugins": [{ "package": "/path/to/oc-machine", "options": {
  "dataDirectory": "/abs/path",   // default $XDG_DATA_HOME/oc-machine (~/.local/share/oc-machine)
  "redactAllTools": false,        // also mask secrets in every native tool's output
  "guardDataDirectory": false     // deny native file tools inside the data directory
} }] }
```

## Install

Requires [OpenCode](https://opencode.ai) 2.2.6+ (CLI or Desktop) and [Pixi](https://pixi.sh); macOS or Linux.

```sh
git clone https://github.com/p-w-rs/oc-machine.git && cd oc-machine
pixi run --locked install          # runs the tests, then installs a verified snapshot into your OpenCode config
```

Restart OpenCode (or `/reload`). Then open **Settings → Machines** (or `/machines` in a session).
Agents can also set things up for you when you ask.

```sh
pixi run --locked install-status   # what is installed, and whether its files are intact
pixi run --locked rollback         # back to the previous snapshot
pixi run --locked uninstall        # removes only this plugin's entry; your data stays
```

Updating: `git pull && pixi run --locked install`. Your accounts, sign-ins and permissions live in
`~/.local/share/oc-machine` and survive updates; move them between computers with **Export** / **Import** in the view.

## Development

```sh
pixi run --locked test         # typecheck + tests (pinned OpenSSH; a throwaway sshd on 127.0.0.1)
pixi run --locked smoke-host   # real OpenCode 2.2.6 CLI, isolated home, scripted model, throwaway sshd
pixi run --locked doctor
pixi run --locked install-dev  # point your OpenCode config at this checkout
pixi run desktop-dev start --sample   # isolated OpenCode Desktop (own profile, port, data) for GUI checks
pixi run desktop-dev stop
```

Linux checks use a UTM VM (`oc-machine-linux-test`, Ubuntu 24.04 arm64 cloud
image, cloud-init over a local HTTP seed, SSH on 127.0.0.1:2232). Its key and
ssh config live in `.local/linux-vm/`; copy the committed tree in with
`git archive HEAD | ssh -F .local/linux-vm/ssh_config ocm-linux "tar -xf - -C /work"`.

```sh
```

Tests never touch your real `~/.ssh`: the test sshd gives sessions a temporary
`HOME`, test machines use their own known_hosts, and the suite fails if
`~/.ssh/authorized_keys` or `known_hosts` change.

## Security notes

Usability first; this is a large step up from agents reading raw env vars, not
a hard boundary. A value supplied to a command is visible to that command, so
the agent could print it in an encoding the masking misses. Per-command files
(config, keys, askpass answers) live in a private run directory removed shortly
after the command. The vault key is a 0600 file next to the vault.
