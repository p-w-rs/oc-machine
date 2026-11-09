# oc-machine

Machines and env vars for OpenCode agents. The plugin tells the agent what
exists (machines, env vars with descriptions); the agent uses them **from its
own shell**, and the plugin supplies the values to that one command after a
permission check. macOS and Linux. Requires OpenCode 2.2.6+ and Pixi.

**Status:** machine and env var setup, ssh (agent, key + passphrase, password,
generated keys, jump hosts, forwarding), sudo, permissions, masking, the
Review-pane / Settings GUI and encrypted export/import work. Installer polish
and a Linux check are next.

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

## Development

```sh
pixi run --locked test         # typecheck + tests (pinned OpenSSH; a throwaway sshd on 127.0.0.1)
pixi run --locked smoke-host   # real OpenCode 2.2.6 CLI, isolated home, scripted model, throwaway sshd
pixi run --locked doctor
pixi run --locked install-dev  # point your OpenCode config at this checkout
pixi run desktop-dev start --sample   # isolated OpenCode Desktop (own profile, port, data) for GUI checks
pixi run desktop-dev stop
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
