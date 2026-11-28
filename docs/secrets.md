# Secrets

## Pasting a key in one step

Copy the key, then ask any agent to run:

    ah secret put NAME

The tool reads the clipboard itself (`pbpaste` on macOS, `wl-paste` or `xclip` on Linux), stores the value, clears
the clipboard, and prints only the name, the store, the version id and the length in bytes. The value never passes
through the agent: it is not in the chat, on a command line, in an environment variable, in a log, or in the output.
Surrounding whitespace is stripped (`--raw` keeps it). If anything fails, the clipboard is left as it was.

Several keys at once: copy one per line and run `ah secret put NAME --lines`. They are stored as `NAME-1`, `NAME-2`,
and so on. For lines such as `<label>|<key>`, run `ah secret put NAME --lines --sep '|' --field 2 --label-field 1`.
The label goes on the secret as a label (an annotation on GCP), never into the value. A label that looks like a key is
refused and nothing is stored.

Other sources: `--from stdin` or `--from file:PATH`.

## Where it lands

| `--to` | Where | How the value gets there |
|---|---|---|
| `gcp` (default) | Google Secret Manager | `gcloud secrets create NAME --replication-policy=automatic` if the secret is missing, then `gcloud secrets versions add NAME --data-file=-` with the value on stdin |
| `keychain` | macOS login keychain, account `ah-secret`, service `NAME` | `security -i` with the command on stdin and the value hex-encoded |
| `file:PATH` | a 0600 file, written atomically | `PATH` is the file itself, or a directory (an existing one, or a path ending in `/`) that holds `NAME` |

`--project P` picks the GCP project. Defaults come from `~/.agent-harness/secrets.json`, for example
`{"store": "gcp", "project": "my-project", "keychain_account": "ah-secret"}`.

A note on the keychain: `security add-generic-password -w VALUE` (and `-X HEX`) puts the value on the command line,
where any process of the same user can read it while it runs. The prompt form (`-w` given last) reads from the
terminal, not from a pipe. So `ah secret` sends the whole command to `security -i` on stdin. When the tool reads the
value back, `security find-generic-password -w` may print a value that is not plain text as hex.

## How tools read it

    ah secret exec --env OPENAI_API_KEY=OPENAI_KEY -- python3 tools/run.py

This fetches each secret and runs the command with the values in that command's environment only. Anything the
command prints has those exact values replaced with `[REDACTED:ah-secret]`. Values shorter than 4 bytes are not
masked. The command's exit code is passed through. Nothing judges the command after `--` (release 1001 deleted the
command guard), and `ah secret` runs outside the sandbox (docs/sandbox.md, harness tools), so the command does too.

`ah secret list` prints names only. `ah secret rm NAME` deletes a secret. It runs only for the owner (a terminal
outside any agent) or a session launched or recorded as a supervisor; a worker or reviewer is refused with the
command the owner runs (`ah_roles.launch_role`).

Programs that read a key file themselves (`ssh -i KEY`, `--key-file=PATH`, `docker run --env-file .env`, a dotenv
loader) are fine. Pass them the path.

## Who may read secrets directly

Since release 1001 no hook reads a command, so nothing refuses `cat .env` or `printenv` by its text. What holds is the
sandbox a session is launched with (docs/sandbox.md): the key files in `secret_paths` (`~/.ssh`, `~/.aws`, `~/.codex/
auth.json`, `~/.config/gcloud`, `~/.config/goodqa`, the owner's key files under `~/.config`, `~/.git-credentials`,
`~/.npmrc` and the rest) cannot be read by any role's shell, and `Read(**/.env)` and its siblings deny project `.env`
files to the Read tool and the file commands Claude Code recognises. `ah doctor` lists the credential-shaped files
that no role denies (`secrets-readable`); add them to `local.json` `sandbox_extra_deny_read`.

Not covered, stated: a session launched without the role file (today, every session until the rollout) has no such
boundary; the gh token in the login keychain stays usable (pushing needs it); `printenv` prints whatever the session's
own environment holds. Fable and Astra mean nothing to the boundary: the role comes from the launch file.
