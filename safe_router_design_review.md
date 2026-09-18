# Safe Router — Design Review

Skeptical systems-security review of the threat model, problem decomposition, and build plan. 2026-08-14.

Labels used throughout, per your ground rules: **[cited]** = a retrieved source establishes it; **[practice]** = well-established engineering/security practice; **[inference]** = my reasoning or speculation. Scope decisions incorporated from your answers: v0 is single-machine (loopback), Claude Code disposition is open (recommendation below), inbound-channel exposure is uncertain but that traffic is mostly non-sensitive (worst case: contact information).

---

## 0. Sourcing check — I retrieved every source before writing this

| Source | Retrieved? | Verdict on your summary |
|---|---|---|
| "Your Agent Is Mine" (2604.08407) | Yes (abs + HTML) | **Accurate.** 28 paid / ~400 free routers; 9 injecting malicious code (1 paid + 8 free); 17 touched researcher AWS canary credentials (the paper adds one that drained ETH from a planted key); conditional delivery confirmed, including ~50-call warm-up triggers and targeting of autonomous "YOLO mode" sessions. One precision note: the paper reports the **fail-closed policy gate** blocking shell-rewrite samples at 1.0% FP, and response-side anomaly screening flagging 89% of AC-1 — your "~89% at ~1% FP" merges two defense results. Directionally fine. |
| RerouteGuard (2601.21380) | Yes | **Accurate.** Confounder gadgets prepended to queries; attacker objectives = cost escalation, quality hijacking, safety bypass; embedding-based detection with adaptive thresholding (claims >99% detection). |
| "Model Routing Is a Risk Management Problem" (AI After Hours) | Yes | **Slightly generous.** Actual title is "Model Routing Is *Now* a Risk Management Problem," and the risk-concentration argument is one motivation among several — the core of the piece is economics (cost/latency, model commoditization, "build the routing layer"). Your key observation — **silent on risks introduced by the routing layer itself** — confirmed. |
| ACRouter (2606.22902) | Yes (HTML) | **Accurate.** Orchestrator / sandboxed Verifier / Memory keyed by task embeddings, Context-Action-Feedback loop, contextual-bandit framing, strong out-of-distribution results — and, as you said, **zero threat model or security discussion of any kind**. |
| Routing/cascading survey (2603.04445) | Yes | **Accurate.** Confirmed it does not address verification, attestation, or confidential computing. |
| RASA (2602.04448) | Yes | **Mostly accurate.** Core claim confirmed: naive full-parameter safety fine-tuning on MoE reduces attack success "through routing or expert dominance effects, rather than by directly repairing Safety-Critical Experts." Your specific phrasing — "restoring original routing collapses the apparent safety gain" — is a stronger operational claim than I could verify verbatim from what I retrieved. Treat that sub-claim as plausible but unverified at that specificity. |
| "Sparse Models, Sparse Safety" (2602.08621) | Yes | **Accurate on the headline** (masking 5 routers in DeepSeek-V2-Lite raises ASR >4× to 0.79; their F-SOUR attack reaches 0.90–0.98). "Safety-critical routers cluster in specific layers" is supported in spirit — the paper scores per-layer router safety criticality (RoSais) — but the abstract doesn't state clustering explicitly. |
| LiteLLM 2026 CVE record | Yes (Red Hat, Obsidian Security, Sysdig, The Hacker News) | **Verified, two precision fixes.** CVE-2026-35030 = OIDC userinfo cache key collision → auth bypass/priv-esc ✓. Low-priv→admin→RCE chain ✓ = CVE-2026-47101 (internal user mints keys with arbitrary `allowed_routes`) → CVE-2026-47102 (self-promotion to `proxy_admin` via `/user/update`) → CVE-2026-40217 (Custom Code Guardrails `exec()` sandbox escape → host RCE). CVE-2026-42208 = SQL injection in the auth path, exploitation observed ~36h after disclosure ✓. Fixes: (a) the chain ran through **key/user-management and guardrail endpoints**, not literally an "unguarded config endpoint"; (b) what I can verify on storage is **plaintext credentials in env vars + DB encryption under `LITELLM_SALT_KEY`** — not "unsalted/plaintext password storage." Neither correction weakens your point; the guardrails-`exec()` CVE *strengthens* it, since it's exactly a feature class a single-user router would never carry. |

One thing the CVE record adds that your taxonomy misses: the Obsidian chain's endgame was **compromising downstream AI agents via response injection** — class (3) collapsing into class (1) on compromise. Your four classes are rightly separable for provenance and fix, but they **compose in failure**. Keep the taxonomy; add the edge. [cited]

---

## 1. Strongest objections, in order

### Objection 1 — Your invariant is enforced by an if-statement, not by structure

"Structurally enforces" is the load-bearing phrase of the entire project, and the proposed v0 doesn't deliver it. One process that evaluates per-key policy *and* holds remote provider credentials *and* has remote egress means the local-only floor is a branch in your code. One logic bug in policy evaluation — or one bad config merge at 11pm — and the floor is gone silently. [inference]

The fix is nearly free given your design: **split-plane**. Run two instances of the same binary with different configs. The **safe plane** serves sensitive-tier keys and its config contains *no remote backends and no remote credentials* — a policy bug in that process cannot spend credentials that don't exist. The **escalation plane** holds the remote keys and only knows escalation-capable keys. A sensitive client's key simply doesn't exist on the escalation plane. This is standard privilege separation [practice], it turns "no path degrades into a remote call" from a code-correctness claim into a process-property claim, and it costs you a second config file and a second launchd plist. Optional hardening, later: run the safe plane as a dedicated UNIX user with a PF egress rule (loopback only) so even a full compromise of that process has no route out. [practice]

This also gives you the auditable artifact your consultancy positioning wants: "here is the config of the process my sensitive clients talk to; observe that it contains no remote anything."

### Objection 2 — The router's single strongest value is missing from your writeup: key custody consolidation

Today, every client that might ever escalate holds a frontier API key. After the router, **no client holds any remote credential** — remote keys exist in exactly one process, ideally in the macOS Keychain with access restricted to the signed router binary [practice]. That converts "compromised or confused client exfiltrates via its own remote API access" into "compromised client can talk only to the router, under a key whose ceiling is pinned."

This matters because it's also the correct answer to the strongest version of the don't-build argument (§7): pointing clients directly at LM Studio gets you the confinement, but it leaves remote keys scattered across every client that also does non-sensitive work. Custody consolidation is the thing only a chokepoint gives you. Name it in the spec; let it drive scope. [inference]

### Objection 3 — The invariant's boundary is unstated, and you will eventually oversell it to yourself

"Client data never escapes to a third party" quietly means "**on the inference hop**." Two adjacent leaks:

- **Upstream:** anything arriving via a hosted chat gateway has already transited that provider's servers before your first byte of inference. You say this channel is mostly non-sensitive, worst case contact information — fine, but *write that acceptance into the threat model*, because "mostly non-sensitive" is exactly the kind of scope that erodes when someone starts pasting documents into a chat thread. Same audit for every inbound channel (email, webhooks, MCP servers) if any executes off-machine.
- **Downstream:** the router cannot stop a client from leaking what it *receives*. A compromised MCP server or agent tool that legitimately holds a local-only key gets the model's answer and can relay it anywhere it has its own connectivity. Your guarantee is "traffic through me obeys the floor," not "this machine doesn't leak." [inference]

And the boundary you asked about directly: **anything with code execution as your user defeats a user-level router by definition** — a hostile npm postinstall doesn't need to attack the router; it reads configs, or calls api.openai.com itself with its own key. The router's obligations against local malware are only: don't make it worse (no plaintext key files; Keychain; signed binary), and leave good forensics. Declaring this out of scope explicitly is not a concession — it's what makes the in-scope claims honest. [practice]

### Objection 4 — The hashed transparency log, as specified, is security theater

Single writer, single reader, single machine: an attacker or bug with write access to the log file can rewrite the entire chain and recompute every hash. Hash-chaining proves internal consistency, nothing more, unless the chain head is **anchored externally** [practice]. The fix is trivial and preserves the invariant (a chain head is a hash, not client data): push the head hash on an interval to the Mac Mini, a private git remote, anywhere with independent write history. Anchor it, or demote it honestly to "a log."

You asked me to name theater explicitly, so the full list: the unanchored hash chain (above); behavioral fingerprinting via latency/throughput artifacts (drifts with provider infrastructure → alert fatigue → ignored alerts [practice] — the cheap real version is logging requested-vs-returned `model` + usage fields and diffing, which you should do in v0); the PII tripwire (honestly designed because downgrade-only, but see §2); and token counting as a policy input (complexity that buys nothing — see §5).

### Objection 5 — LM Studio is a policy bypass sitting next to your policy engine

Your LM Studio server currently listens on the Tailscale address, and LM Studio's OpenAI-compatible server is unauthenticated [practice — verify on your build]. Any process on the tailnet or localhost can talk to your models directly, around every control you're building. For a loopback-only v0: bind LM Studio to 127.0.0.1 and make the router the only advertised path. When v1 opens the tailnet to the Mac Mini clients, the router must be the *only* off-box listener, or the floor is decorative. The general rule: the router's guarantees only hold if the backends are unreachable except through it. [inference from your stack]

On the browser-page-hitting-127.0.0.1 path you flagged: your existing design already kills it. Mandatory bearer key on every request defeats drive-by POSTs, and DNS rebinding defeats same-origin policy, not authentication [practice]. Add `Host`/`Origin` validation as cheap hardening and move on — this one is solved, and it's worth noticing that it was solved by the per-key design, not by anything you still need to build.

### Objection 6 — OpenRouter as an escalation backend re-imports the adversary class your corpus measures

"Your Agent Is Mine" is about unaccountable aggregating intermediaries; OpenRouter is a (reputable) aggregating intermediary that terminates TLS and sees plaintext [cited: your own corpus's framing]. Escalating client-adjacent traffic to it partially undoes the project's premise. Make the remote ladder three rungs, not two: **local → remote-first-party** (Anthropic/OpenAI direct, with ZDR/data-retention controls where offered [practice]) **→ remote-aggregator** (OpenRouter, for keyless experimentation and personal traffic only, never client-adjacent). Your key-bound policy already supports this; it's one more tier value in the config.

---

## 2. Threat model — wrong, overweight, missing

**Wrong (small but load-bearing).** "Every LiteLLM CVE I found lives in a feature a single-user local router has no reason to implement." *Almost.* You are re-implementing miniatures of three of those features: an auth path (per-client keys), a policy store, and a log. CVE-2026-42208 was SQL injection in the auth path [cited]. The lesson isn't "single-user routers have no auth path" — it's that yours must be too boring to attack: constant-time comparison against argon2 hashes loaded from a static file, no database, no parser, no query language anywhere near authentication. [practice] The honest version of your claim: single-user deletes the network-facing multi-tenant *control plane*, and what remains must be aggressively dumb.

**Wrong (already caught via your answer).** The proposed v0 said loopback bind while the client list included processes on a second machine. Resolved: v0 is single-machine. Carry the consequence consciously — v0 does *not* cover the chat-gateway agent, arguably the riskiest client (untrusted internet input driving semi-autonomous tool use). That's an argument for shipping a thin v0 fast and getting to the tailnet v1, not for gold-plating v0.

**Overweight: adaptive routing as a *security* threat.** Your rejection is right where the decision crosses the sensitivity boundary — RerouteGuard-style gadget manipulation and persistent memory poisoning are real [cited]. But the confidentiality argument does not apply to learned selection *among local-only models*: worst case there is quality/availability manipulation, never disclosure. Deterministic-everywhere is still the correct v0 call on simplicity grounds, but your stated reason overreaches, and it matters later: adaptive selection within the local tier (ACRouter-style, even) would not be a security regression, provided the *floor* decision stays deterministic and key-bound. The floor stays dumb; the shelf can get smart. [inference]

**Overweight: response-side screening and the PII tripwire.** The tripwire is honestly designed — downgrade-only, so adversarial manipulation yields DoS, fail-closed. But look at what it guards: requests *already authorized remote by their key*. It's a guard against your own key-misassignment, purchased with a content classifier in the hot path and real-world PII recall that is mediocre on exactly the data that matters [practice]. The cheaper guard for the same failure mode is default-deny key issuance: new keys are local-only until explicitly promoted, escalation-capable keys are few and individually named. Slot the tripwire v2, or never.

**Missing, beyond the objections above:**

- **Malicious model files — two distinct threats.** (a) Parser exploitation: weights-file parsing in llama.cpp-family loaders has a CVE history; treat model files as untrusted input — pinned sources, checksums, prefer safetensors/MLX formats, never pickle-adjacent [practice]. (b) Backdoored behavior: a poisoned local model sees your most sensitive data *by design*. Its output only reaches clients, so exfiltration needs a client-side channel — but a backdoored model plus an agent with tools is a confused-deputy pair. The mitigation is procurement discipline (which models you pull, from where), not a router feature. Your RASA / Sparse-Safety citations bear on this [cited]: MoE safety alignment is brittle under routing manipulation, which is an argument for encoding *which local models the agentic clients may drive* as key→model allowlists — your design already supports this; use it.
- **You-in-a-hurry as the adversary.** The most probable violator of the floor in year one is your own config change. Delete the class: no admin API, no config endpoint, no in-app settings. Policy is a static TOML in git, loaded at startup, SIGHUP reload with full validation and keep-old-on-invalid. LiteLLM's escalation chain ran precisely through endpoints that mutate policy at runtime [cited].
- **The composition edge** (3)→(1) from §0: a compromised router is the perfect intermediary adversary. Your defense is minimizing class (3) surface, which you're doing — but it belongs in the model explicitly, because it's the reason the supply-chain item (9) deserves its accept-and-slot status rather than "later."

---

## 3. Problem decomposition — verdicts item by item

**(1) Tagging — solved. Stop listing it first.** Key-as-policy-identity is correct, it's the universal zero-cooperation mechanism you describe, and it's consistent with the client-side defensive stance your strongest paper takes [cited: "Your Agent Is Mine" proposes client-side defenses]. The residual problem is not classification, it's **key hygiene**: issuance defaults (default-deny remote), naming (one key per client, named for the client), rotation, and the human-error case of pasting an escalation-capable key into the wrong client's config. Demote (1) to "decided"; promote a key-hygiene checklist into the spec.

**(2) Protocol fidelity — dissolve it, don't solve it.** Full judgment in §5. Preview: with passthrough-first and OpenAI-compat-only backends, v0 contains *zero* schema translation, and the problem you expect to kill the project is deferred entirely rather than partially solved.

**(3) Streaming vs. screening — a non-problem in v0** by your own scoping line ("no screening — those are v1+"). Once screening is out, streaming is plumbing (SSE proxy with backpressure and cancellation), not semantics. Tool-call delta buffering returns only if response screening ever earns its way in.

**(4) Failure semantics — correctly weighted.** The entire item compresses to one rule plus a matrix (§4). Note that "graceful degradation is the bug" generalizes further than you stated: **silent model substitution is the bug in both directions**. Remote→local fallback is confidentiality-safe but integrity-corrupting — the client believes it got frontier output. No automatic substitution, ever, in any direction.

**(5) Process boundary — correctly weighted, and mostly already answered** by loopback bind + mandatory keys + Host/Origin checks + LM Studio bound to loopback (§1, Objection 5). Split-plane (§1, Objection 1) is what turns the remainder from policy into structure.

**(6) Adequacy signals for cascade — a non-problem. Delete it.** You already rejected cascade: escalation is an explicit client act, so the router never judges adequacy. Keeping this on the list is the camel's nose for the content inspection you swore off. If a client wants to decide "local wasn't good enough, retry remote," that's client logic operating on its own outputs, and it hits the router as a fresh request under an escalation-capable key.

**(7) Observability — keep, but metadata-only by default.** Request metadata (timestamp, key, model requested/returned, token usage from the backend's own usage block, latency, disposition) — never content — for local-tier keys. Two reasons: the plaintext-log liability you already named, and client-data obligations that may include deletion — hashed metadata survives a deletion request; stored prompts don't [inference/practice]. Content capture, if ever, is per-key opt-in.

**(8) Verifiable model identity — accept-and-slot is right.** Do the trivial 20% in v0: log requested vs. returned `model` field and usage stats per response, and count mismatches. Skip behavioral fingerprinting (§1, Objection 4).

**(9) Supply chain — correctly weighted, under-specified. This is where I'll push hardest on your instincts.** The enforcement plane should be a **headless Rust daemon** with a minimal mainstream dependency set (tokio + hyper/axum, rustls, serde — each heavily vetted [practice]) — **no Tauri, no npm, no WebView, no GUI in the security-critical process**. Your Tauri instinct is your shipped-stack instinct, and it's wrong here: Tauri drags an npm dependency tree and a web renderer into the exact process whose compromise voids every guarantee, and hostile-npm-postinstall is literally on your own locally-originating threat list. If you want a dashboard later, make it a separate process that reads the log and *cannot write policy*. Concrete hygiene from day one, all cheap now and expensive later: `cargo-audit` + `cargo-deny` in CI, pinned lockfile, signed and notarized builds, **no auto-update** (manual updates only — an auto-updater is a remote code execution channel with a nice UI [practice]).

---

## 4. The failure matrix

**The one rule, stated once:** *Every failure is terminal within the tier the key authorizes. The router never re-dispatches across the local→remote boundary for any reason — not on error, not on timeout, not on overflow, not on quota. Escalation exists only as a fresh client request under an escalation-capable key. Silent model substitution never happens in any direction.*

Everything below is that rule applied. This table is also your v0 integration-test list — write the tests from these rows.

| # | Failure mode | Correct behavior (invariant-preserving) |
|---|---|---|
| 1 | Local backend down / connection refused (LM Studio not running) | 502 in well-formed OpenAI error JSON. No fallback, no retry elsewhere. |
| 2 | Requested model unknown / not loaded | Surface the backend error verbatim. Alias resolution is a deterministic static map; aliases never cross tiers. |
| 3 | Context overflow on local model | Pass through the 400. Never "retry on a bigger remote model" — this is the single most tempting violation, name it in the spec. |
| 4 | Stream stalls mid-generation (idle timeout) | Terminate the SSE with a proper error event. No re-dispatch. |
| 5 | Remote 429 / quota / 5xx on an escalated request | Pass through. The client decides. No downgrade-to-local either (integrity). |
| 6 | Router crash mid-stream | Client sees dropped connection; on restart, no replay, no persisted request state. |
| 7 | Config invalid at startup | **Refuse to start.** Never "start with defaults" — default-anything is a policy you didn't write. |
| 8 | Config reload (SIGHUP) invalid | Keep the old config, log loudly. |
| 9 | Unknown / revoked key | 401. Constant-time compare. No detail leakage about which part failed. |
| 10 | Local-only key requests a remote model / escalation flag | 403 with a **distinct machine-readable code**. Your clients are agents: ambiguous errors get retried in loops; policy denials must read as permanent. |
| 11 | Log write failure / disk full | Traffic continues; buffer in memory; set a visible degraded flag. Availability beats log completeness for a single user — accept that the transparency claim weakens in this state. |
| 12 | Returned `model` ≠ requested model | Pass through + log + increment mismatch counter (this is v0's entire "model identity" feature). |
| 13 | TLS/cert failure to a remote backend | Fail closed. No plaintext retry, no cert-pinning bypass flag. |
| 14 | Client disconnects mid-request | Cancel the upstream request, log partial usage. |
| 15 | Split-plane confusion: safe plane receives an escalation request | 403 (policy denial). Escalation plane receives a sensitive-tier key → 401 (the key does not exist there — which is the point). |

---

## 5. The protocol-fidelity judgment

You think the project realistically dies here. It dies only if you *model schemas*. There is a middle path narrower than both a hand-rolled implementation and a vetted gateway dependency: **passthrough-first**.

- **v0: one inbound dialect** — OpenAI chat completions (`/v1/chat/completions` + `/v1/models`) — and **backends that already speak it natively**: LM Studio does; OpenAI does; OpenRouter does; Anthropic exposes an OpenAI-compatibility layer for basic chat [practice — verify current tool-use coverage before relying on it]. The router parses the request body *only enough for admission*: bearer key, `model`, `stream`, presence of `tools`. Response bytes stream through untouched.
- **Consequence: zero schema translation exists in v0.** The admission decision — the only security-relevant decision — happens before the first upstream byte and does not depend on understanding the payload. Fidelity isn't partially solved; it is deferred *entirely*, which is the only version of deferral that doesn't leak complexity back into the build.
- **Token counting as a policy input: cut it.** It requires per-model tokenizers, drifts with model versions, and buys you nothing that `max_tokens` + the tools-presence flag + key identity don't already give you. [inference]
- **Claude Code (your question):** keep it pointed directly at Anthropic in v0. It's your least-sensitive client — already frontier-bound by nature — and it speaks Anthropic Messages. Your multi-LLM ambition lands in v1 as a **second inbound passthrough dialect**: Anthropic Messages in → Anthropic backend out, byte passthrough, admission at the front. That's cheap because it's the same trick. What you should not build, possibly ever: **cross-dialect translation** (Anthropic-in → OpenAI-out or the reverse). Per-dialect passthrough scales linearly; translation scales combinatorially, and it is precisely the attrition death you predicted — the good news is that it's severable, and everything of security value survives without it.
- **Buy vs. build within the narrow scope:** typed request structs from a crate like `async-openai` are fine for admission parsing [practice]; adopting a gateway *framework* is not — the framework's feature surface is the thing this project exists to not have.

---

## 6. Build plan

**Phase 0 — half a day, paper only.** Write the one-page spec: the invariant with its boundary statement (§1, Objection 3), the one rule + failure matrix verbatim (it doubles as the test plan), the key-hygiene checklist, and the three regret-decisions recorded as decided: split-plane (yes), static-config-no-admin-surface (yes), no-GUI-in-daemon (yes). These three are the decisions you'd regret most getting wrong early, because each is nearly free now and a rewrite later.

**Phase 1 — v0, in work order:**
1. Daemon skeleton: axum/hyper, loopback bind, bearer-key auth (argon2 hashes in static TOML, constant-time compare), Host/Origin validation.
2. Passthrough SSE proxy to LM Studio (same dialect, byte-level), with backpressure and cancellation.
3. Admission policy: key → (plane, model allowlist, tier), distinct 401/403 codes.
4. Escalation plane: same binary, second config, one remote first-party backend, provider key from Keychain.
5. Failure matrix rows 1–15 implemented and tested.
6. Metadata log; requested-vs-returned model diff; hash-chain only if you also build the anchor push, otherwise plain log.
7. Sign + notarize; `cargo-audit`/`cargo-deny` in CI; pinned lockfile.

With your Rust background and this scope, this is on the order of one to two focused part-time weeks [inference]. If it trends meaningfully past that, you are building v1 features — stop and check which one.

**Phase 2 — v1:** tailnet bind for the Mac Mini clients (LM Studio moves to loopback everywhere; router becomes the only off-box listener); Anthropic Messages as a second passthrough dialect (Claude Code and the Tauri app can then route through); log-head anchoring; read-only status UI as a separate process.

**Phase 3 — only if earned by an actual incident or client requirement:** tool-call buffering + response screening; PII tripwire; adaptive selection *within* the local tier.

**Never (as defaults, revisit only with a written reason):** cross-dialect translation; any runtime-mutable policy surface; auto-update; multi-user anything; cascade/adequacy logic.

---

## 7. Should you build it at all — the honest 80/20

The security property alone does not require a router. Pointing sensitive clients directly at loopback-bound LM Studio, removing remote keys from those clients, and adding an outbound firewall rule gets roughly 80% of "sensitive traffic cannot escape" for roughly 2% of the effort. None of your reference implementations change this, and one of them is instructive as an anti-pattern: I retrieved OmniRoute — Node/Next.js, web dashboard, Electron builds, MCP integration, ~291 providers, and **keyless free remote providers pre-wired into the default `auto` combo**. It's built to *maximize* provider reach; your problem is *minimizing* it. The category "local-first router" optimizes aggregation. Nothing on your list even attempts confinement as the product. That's the gap, and it's real.

What the 2% alternative does not give you — and what justifies the build:

1. **Key custody consolidation** — no remote credential in any client, ever (§1, Objection 2). This is the big one and the one direct-to-LM-Studio can't replicate for clients that also do non-sensitive work.
2. **Protection against client misconfiguration** — a client pointed anywhere wrong, with no key, gets nothing, instead of silently working.
3. **One uniform metadata log** across all model traffic on the machine.
4. **An auditable floor** — "show me the config of the process client X talks to" is a one-file answer, which is worth actual money in your client conversations. [inference]

So: **build it — but build the version in §6, not the version in your prompt.** The PII tripwire, response screening, fingerprinting, and multi-dialect ambition are where 10% of additional security property costs several hundred percent of additional effort, and where a solo project with billable-hours pressure actually dies. The thin v0 is small enough to finish, delivers all four of the real benefits, and — because narrowness is the security property, as you correctly concluded — every feature you decline is also a security decision in your favor.

---

## Appendix — direct answers to your checklist

- **Security theater named:** unanchored hash-chained log; behavioral fingerprinting; token-count policy input; (borderline) PII tripwire.
- **Easy problem solved next to an open hard one:** tagging solved via keys while key issuance/custody/rotation discipline was unspecified; the inference hop hardened while inbound-channel exposure (chat gateways et al.) was undocumented as an accepted risk; response `model`-field logging specified while the log itself lacked an external trust anchor.
- **Locally-originating attack paths, disposition:** malicious browser page → solved by mandatory keys + Host/Origin checks; hostile npm postinstall / local malware → out of scope by declared boundary (Keychain + signing limit blast radius; router cannot defend against user-level code exec); compromised MCP/agent tool → confused deputy holding a legit key: floor holds (can't escalate), but client-side relay of received outputs is out of scope — say so; malicious model file → parser hygiene + procurement discipline + per-key model allowlists for agentic clients.
- **Failure matrix:** §4, fifteen rows, one rule.
- **Protocol fidelity:** middle path exists — passthrough-first, per-dialect, zero translation (§5).
- **Build at all:** yes, thin (§7).
