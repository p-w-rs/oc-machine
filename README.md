# oc-machine

Machines for OpenCode: SSH settings, sudo password, env vars and a permission
table per machine. The agent sets machines up; you enter secrets and own the
permissions. macOS and Linux. Requires OpenCode 2.2.6+ and Pixi.

**Status: milestone 2.** Machine config, SSH config generation, shell env vars
and the permission engine work. `machine_exec` / sudo / key generation
(milestone 3) and the Review-pane GUI (milestone 4) are not built yet. Until
the GUI lands, enter secrets with `pixi run secret-set`; permissions use the
defaults below (the table editor arrives with the GUI).

## What it adds, and what it never changes

Adds: six `machine_*` tools, a generated `ssh_config`, and env vars in new
agent shells. Never: denies or prompts for native tools, rewrites native tool
output, edits `~/.ssh/config`, or overwrites an env var your shell already has
(unless that variable is marked `override`). If the plugin hits an error, it
disables itself or skips the addition; OpenCode keeps working as usual.

## Agent tools

| Tool | |
|---|---|
| `machine_list`, `machine_get` | Config, which secrets are set (never values), and what this agent may do |
| `machine_upsert` | Create/update/rename a machine; `local: true` marks the host OpenCode runs on. SSH settings are checked with `ssh -G` before saving |
| `machine_remove` | Delete a machine with its secrets and permissions (asks by default) |
| `machine_request_secret` | Ask you for `sudo`, `ssh-password`, `key-passphrase` or `env:<NAME>` |
| `machine_ssh_config` | Show the generated config |

The agent connects with `ssh -F "$OCM_SSH_CONFIG" <machine-id>`.

## Entering secrets

```sh
pixi run secret-set <machine> <slot>     # prompts with echo off; or pipe the value on stdin
pixi run secret-unset <machine> <slot>
pixi run secret-list                     # pending requests and stored slots, never values
```

Set `OC_MACHINE_DATA_DIR` if you configured a custom `dataDirectory`.

## Permissions

Each machine has a table: columns `ssh`, `sudo`, `x11`, `agent-forward`,
`manage`, `remove` and one `env.<NAME>` per variable; rows per agent, an
any-agent (`*`) row, and per-session overrides. Cells are allow / ask / deny;
unset cells default to **allow**, except `sudo` and `remove`, which **ask**.
Order: session override, then the agent's row, then `*`, then the default.

- Plugin tools follow the full table. **Ask** uses OpenCode's native prompt; a
  native deny rule in your config still wins.
- The agent's own shell follows the `*` row only (OpenCode's shell hook does
  not say which agent opened the shell), and only **allow** counts there:
  denied or ask env vars are not added, and hosts without ssh allowed are left
  out of the generated `ssh_config`, as are X11/agent forwarding when not allowed.

## Options

```jsonc
{ "plugins": [{ "package": "/path/to/oc-machine", "options": {
  "dataDirectory": "/abs/path",   // default $XDG_DATA_HOME/oc-machine (~/.local/share/oc-machine)
  "redactAllTools": false,        // also mask secrets in native tool output (changes native results)
  "guardDataDirectory": false     // deny native file tools inside the data directory
} }] }
```

## Development

```sh
pixi run --locked test         # typecheck + unit/integration tests (uses the pinned OpenSSH)
pixi run --locked build        # GUI bundle
pixi run --locked smoke-host   # real OpenCode 2.2.6 CLI, isolated home, scripted model
pixi run --locked doctor
pixi run --locked install-dev  # point your OpenCode config at this checkout
```

## Security notes

Usability comes first; this is a large step up from agents reading raw env
vars, not a hard boundary. Secret env vars are injected into the agent's shell
when allowed, so the agent can see them there. The vault key is a 0600 file
next to the vault, readable by anything running as you. Sudo, SSH passwords and
key passphrases will only ever be used inside plugin tools (milestone 3).
