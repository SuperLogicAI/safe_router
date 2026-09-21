<p align="center">
  <img src="assets/safe-router.gif" alt="A padlock emerging from darkness" width="100%">
</p>

# Safe Router

Safe Router is a headless, local-first model router. It keeps designated
clients on approved local backends, brokers explicitly authorized remote
requests, and writes a private metadata log of what was requested, served,
and reported as used. Prompts and responses are never stored in that log.

Its safe-plane guarantee is the main reason to use it: traffic presented
under a safe-plane key is served by an approved local backend or is not
served at all. The escalation plane is separate, with its own keys and
explicitly configured remote providers. Policy is static and validated at
startup; the router does not silently substitute another model or cross
planes.

## Quickstart (macOS, safe plane)

You need Rust, a local OpenAI-compatible backend such as LM Studio listening
on `127.0.0.1:1234`, and a model loaded in that backend. Keep the backend
bound to loopback; see the [deployment checklist](docs/DEPLOYMENT.example.md)
before using this with sensitive requests.

### Agent-assisted setup

To have Claude Code or Codex install and configure the safe plane, open the
agent in the directory where you want Safe Router checked out and paste this
prompt:

```text
Install and set up Safe Router for me from
https://github.com/SuperLogicAI/safe_router.

Follow the repository's README, CLAUDE.md, and docs/DEPLOYMENT.example.md. Set
up the local-only safe plane first; do not configure remote providers or the
escalation plane. Inspect my machine before making changes, preserve and report
any existing Safe Router configuration, and ask before installing a toolchain,
changing settings outside ~/.safe-router, writing a launchd plist, or loading a
launchd job.

Use an OpenAI-compatible local backend bound only to loopback. If I already
have one running, discover its actual model IDs and let me choose the model if
there is more than one reasonable option. If I do not have one ready, explain
the smallest next step and help me complete it. Verify that the backend is not
listening on a LAN or tailnet address before treating setup as complete.

Build Safe Router with its locked dependencies, generate a new sp_-prefixed
client key, store only its Argon2id hash in ~/.safe-router/safe.toml, and allow
the selected local model. Never print the key after the initial handoff or put
it in shell history, source files, logs, or chat summaries. Start the router,
verify /v1/models and a small chat-completions request through it, and give me
the base URL, model ID, and one-time client key so I can configure my client.
If any check fails, diagnose it and keep the safe plane fail-closed rather than
adding a remote fallback. At the end, summarize what you changed, what is
running, and any manual or persistence step that remains.
```

The agent should stop for choices that depend on your machine, such as which
loaded model to allow or whether to install a persistent launchd job. For a
fully manual setup, continue below.

```sh
cargo build --locked
mkdir -p "$HOME/.safe-router"
ROUTER_KEY=$(openssl rand -hex 32)
ROUTER_HASH=$(printf '%s' "$ROUTER_KEY" | target/debug/safe-router hash-key)
```

Print the hash with `printf '%s\n' "$ROUTER_HASH"`, then create
`$HOME/.safe-router/safe.toml` with that hash. Replace `YOUR_MODEL_ID` with
an ID actually loaded in the backend (including any slash in the model ID):

```toml
[server]
bind = "127.0.0.1:8787"
plane = "safe"

[[backend]]
id = "local"
base_url = "http://127.0.0.1:1234/v1"
dialect = "openai"

[[key]]
id = "first-client"
hash = "<paste ROUTER_HASH here>"
allow = ["local/YOUR_MODEL_ID"]
```

Run the router in a second terminal with
`target/debug/safe-router --config "$HOME/.safe-router/safe.toml"`.
From the first terminal, check the connection and make a request:

```sh
curl -H "Authorization: Bearer $ROUTER_KEY" http://127.0.0.1:8787/v1/models
curl http://127.0.0.1:8787/v1/chat/completions \
  -H "Authorization: Bearer $ROUTER_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"model":"local/YOUR_MODEL_ID","messages":[{"role":"user","content":"Hello"}]}'
```

The first response lists available model IDs. If needed, update the
`allow` entry and request model to match one of those IDs, then restart the
router or send it SIGHUP to reload the config.

Keep the key private and give clients only the key for their intended plane.
For the escalation plane, launchd installation, signing, and log anchoring,
follow the [specification](docs/SPEC.md) and
[deployment template](docs/DEPLOYMENT.example.md). The router is not a
sandbox for other programs on the machine; [SECURITY.md](SECURITY.md)
describes that boundary.

## Usage and observability

Safe Router also provides a versioned, read-only SQLite log contract for
independent tools. The field meanings, nullability, trust limits, and reader
setup are in [docs/LOG_CONTRACT.md](docs/LOG_CONTRACT.md).
[Logic Loop](https://github.com/SuperLogicAI/Logic-Loop) could consume that
contract in its own optional panel; it is neither a Safe Router dependency nor
a panel shipped by this repository.

**Development build:** `v_requests_v2` is on `master` and was verified in
a local deployment on 2026-09-13. It is not yet part of a tagged release.
After installing a build that includes v2, a read-only inspection query is:

```sh
sqlite3 "file:$HOME/.safe-router/log.db?mode=ro" \
  "SELECT ts, key_id, model_served, tokens_in, tokens_out, usage_state
   FROM v_requests_v2 ORDER BY id DESC LIMIT 20;"
```

The counters are provider-reported metadata, not a bill or a router token
estimate; NULL means the value was not recorded, while 0 is a reported zero.
An OpenAI stream may have no usage unless its client requests a usage event.
`X-Safe-Router-Tag` is optional, client-supplied attribution with no routing
or policy meaning. There is no rate-limit countdown or interactive account
switch. Independent applications must open the database read-only and treat
the tag as untrusted; see the contract for the full reader requirements.

For the security boundary and deployment prerequisites, see
[docs/SPEC.md](docs/SPEC.md) and
[docs/DEPLOYMENT.example.md](docs/DEPLOYMENT.example.md). To report a
vulnerability, see [SECURITY.md](SECURITY.md) — its out-of-scope section is
the honest half.

## License

Copyright 2026 Super Logic AI. Licensed under the Apache License, Version 2.0
([LICENSE](LICENSE) or <https://www.apache.org/licenses/LICENSE-2.0>).

---

Built and maintained by [Super Logic AI](https://superlogicai.com) — AI automation
for small businesses.

Also from Super Logic AI: **[Logic Loop](https://github.com/SuperLogicAI/Logic-Loop)**,
an open-source macOS app for switching between several concurrent AI coding agent
terminal sessions without losing your own context.
