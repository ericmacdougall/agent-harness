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
masked. The command's exit code is passed through. The command guard still judges the command after `--`.

`ah secret list` prints names only. `ah secret rm NAME` deletes a secret. The command guard allows that only for
Fable, Astra and supervisor sessions. The tool itself cannot tell who is calling it.

Programs that read a key file themselves (`ssh -i KEY`, `--key-file=PATH`, `docker run --env-file .env`, a dotenv
loader) are fine. Pass them the path.

## Who may read secrets directly

Fable and Astra may (the owner's rule, 2026-11-24). For them the command guard drops its secret-read refusals and
appends one line per command to `~/.agent-harness/logs/secret-access.jsonl`. The line holds the rule ids, the tool,
the model and the session. It never holds the command.

Every other agent is refused only when a command would actually read a secret out to the transcript, a pipe, a file
elsewhere or the network. Examples are `cat ~/.ssh/id_rsa`, a bare `printenv` or `env`, `gh auth token`,
`security find-generic-password -w`, `rclone config show` and `cat .env`. The refusal names `ah secret exec` as the
way to proceed. A command that only names a credential location is never refused. That covers sample text in a test
generator, fixtures, heredocs written to a file, grep patterns, comments, commit messages, `--help`, `bash -n`,
`ls` and `stat` of a key file, and `jq 'keys'`. When the guard cannot finish its analysis, secret text alone is
allowed with a note.
