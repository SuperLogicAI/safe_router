# DEPLOYMENT.md — template

Per-deployment operator record required by SPEC §11. **This file is a
template.** Copy it to `docs/DEPLOYMENT.md` (gitignored) and fill it in with
your own machine's facts; the real file is deliberately not published, because
a filled-in copy is a map of your network and your client work.

```sh
cp docs/DEPLOYMENT.example.md docs/DEPLOYMENT.md
```

The spec stays tool-agnostic. Instances of its rules live in your copy.

## Client → plane assignment (SPEC §5.5 default-deny applied)

Default every new client to the **safe** plane. Moving one to the escalation
plane is the deliberate extra step, and it gets a written reason in this table.

| Client | Plane | Note |
|---|---|---|
| `<client name>` | safe | `<why this client's traffic is client-adjacent>` |
| `<client name>` | escalation | `<written reason + date this was decided>` |

## Inbound-channel risk acceptances (SPEC §3)

Channels where content arrives from outside your control, and what you have
decided to accept about them. Each entry gets a date and a revisit condition.

- **`<channel> (accepted <date>)`:** `<what class of content flows through it,
  worst case if it leaked, what change would force a rethink>`

## Recorded exposures

Past states of this deployment that would have voided a guarantee, kept so the
guarantee's *start date* stays honest. Not risk acceptances (above) — those are
ongoing and chosen; these are historical and closed.

Record, for each: what was exposed, the scope, whether request content was
disclosed, the real impact, and **which invariant only holds from which date
forward**. A guarantee with no start date is a guarantee that quietly claims
more than it earned.

- **`<what was exposed> (recorded <date>)`** — `<scope, impact, consequence for
  claims>`

## Addresses on this deployment

Tailnet addresses are `100.64.0.0/10` or `*.ts.net`. A `192.168.x.x` backend is
refused at startup (SPEC §4.1, matrix row 19) — LAN is not tailnet.

| Host | Tailnet | Note |
|---|---|---|
| `<hostname>` (this machine) | `<100.x.y.z>` | LAN `<192.168.x.y>` |
| `<hostname>` | `<100.x.y.z>` | needs its own LM Studio loopback check |

## Prerequisites checklist

- [ ] **LM Studio bound to loopback.**
  `lms server stop && lms server start --port 1234 --bind 127.0.0.1`.
  Verify `127.0.0.1:1234` reachable and `<your-LAN-ip>:1234` refused.
  **`--bind` is not persisted by the GUI toggle — it is a per-invocation
  flag.** If LM Studio restarts (app relaunch, reboot, upgrade) it reverts to
  `0.0.0.0` and must be restarted with this command again. Re-verify after
  every LM Studio upgrade or restart, on every node. While LM Studio listens
  on a LAN or tailnet address, every control in this project is decorative:
  anything on that network can query the models directly, bypassing the
  router.
- [ ] Ports 8787/8788 free (`lsof -nP -iTCP:8787 -sTCP:LISTEN`).
- [ ] Escalation provider credential in Keychain, e.g. `safe-router/openai`.
      Not needed if you run the safe plane only.

## launchd jobs

The plists in `launchd/` are templates containing `__SAFE_ROUTER_HOME__`.
Substitute your own path before loading:

```sh
for p in launchd/*.plist; do
  sed "s|__SAFE_ROUTER_HOME__|$HOME/.safe-router|g" "$p" \
    > "$HOME/Library/LaunchAgents/$(basename "$p")"
done
```

**Never `cp` a new binary over the path a running plane has open** — that
corrupts its code signature and the kernel then SIGKILLs every future exec of
that path, silently. Redeploy with temp-file + `mv` (atomic rename).

## v1 log-head anchor

Remote: any operator-controlled append-only remote (SPEC §11 Q4). Set
`ANCHOR_REPO_URL` to yours; `scripts/anchor-push.sh` requires it and ships with
no default, so nothing pushes to an unintended remote.

Recommended: a dedicated repo with branch protection on `main` (no force-push,
no deletion). Anchor commits are hash + row id only by design.

Local mirror: `$SAFE_ROUTER_HOME/anchor-repo` (cloned/pulled by the script,
deployed to `$SAFE_ROUTER_HOME/bin/anchor-push.sh`). Pushed on an interval by
`com.superlogicai.safe-router.anchor` (launchd, `StartInterval` 3600s).

The anchor is what makes the log's "tamper-evident" claim sayable at all. Until
the head is pushed off-box, anything that can write the log can rewrite the
chain and recompute every hash — see SPEC §8.2.

---

**Copying the live log:** `sqlite3 log.db ".backup <path>"`, never `cp`. A
filesystem copy of a database in WAL mode gives a silently stale copy, not an
error, and `verify-log` will happily report "chain OK" against data that is
simply wrong.
