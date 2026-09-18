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

## Usage and observability

Safe Router also provides a versioned, read-only SQLite log contract for
independent tools. The field meanings, nullability, trust limits, and reader
setup are in [docs/LOG_CONTRACT.md](docs/LOG_CONTRACT.md). Logic Loop could
consume that contract in its own optional panel; it is neither a Safe Router
dependency nor a panel shipped by this repository.

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
