# Security Policy

## Reporting a vulnerability

Email **contact@superlogicai.com** with "safe-router" in the subject. Please
do not open a public issue for anything that would let someone defeat the
safe-plane guarantee before there is a fix.

Expect an acknowledgement within a few days. This is a single-maintainer
project with no paid triage rotation and no bounty; timelines are best-effort,
and saying so up front is more useful than a number nobody meets.

## What is in scope

The invariant is: **traffic presented under a safe-plane key is served by a
local backend or it is not served at all** (SPEC §2). The most valuable reports
are ones that break it. Concretely:

- A request on a safe-plane key reaching a remote provider, by any path.
- Cross-plane key acceptance, or startup validation failing to reject a key
  hash present in both planes' config.
- Silent model substitution in either direction (SPEC invariant #6) — a
  remote→local downgrade counts, even though it leaks nothing.
- Anything in the auth path: timing leaks in key comparison, argon2id
  verification bypass, parser behavior on malformed bearer tokens.
- Policy evaluation accepting a config that the documented rules say must be
  refused, or a SIGHUP reload leaving the daemon on a config that failed
  validation.
- Log-chain forgery that `verify-log` reports as intact — within the limits
  below.
- `X-Safe-Router-Tag` handling: injection through the tag into the log, or the
  tag influencing routing or admission in any way. It must be inert.

## What is out of scope

These are documented properties, not bugs. They are listed because knowing what
this tool does *not* defend against is part of using it correctly.

- **Local code execution.** Anything already running as your user can read the
  config, the log, and the Keychain items the daemon uses. The router is not a
  sandbox (SPEC §3).
- **Non-credentialed egress.** A keyless safe-plane config stops the router
  from calling out. It does nothing about side exits: crash reports, DNS,
  telemetry in a dependency, logs shipped somewhere. The PF egress lock that
  would close this is specified and **not yet implemented** — treat the safe
  plane's guarantee as covering credentialed egress today.
- **Backends reachable by a second path.** The guarantee assumes the router is
  the only route to your local backends. LM Studio's OpenAI-compatible server
  is unauthenticated; if it is bound to anything but loopback, every control
  here is decorative. Verify after every LM Studio upgrade or restart.
- **Log tamper-evidence without an off-box anchor.** Single machine, single
  writer: anything that can write the log can rewrite the chain and recompute
  every hash. The claim is "tamper-evident against edits made before the last
  anchored head" and no more (SPEC §8.2).
- **Key issuance.** The router guarantees the two planes' key sets do not
  overlap. It cannot know whether a given key went to the right client. Handing
  an escalation-plane key to a client that handles sensitive data defeats the
  guarantee with no error and no log line.
- **Denial of service** against a single-user loopback daemon.

## Supported versions

`master`. There is no long-term support branch and no auto-update mechanism —
by design; an auto-updater is a remote code execution channel with a nice UI.
Updates are manual, from signed builds.
