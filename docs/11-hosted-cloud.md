# 11 · Hosted Cloud — a control plane across your gateways

> Status: **v1 implemented** (`crates/cloud` + gateway `CloudSink`). A Rust
> control plane ingests telemetry from many gateways and serves an aggregated,
> per-organization view through an embedded web dashboard. Runs anywhere Docker
> runs — no dedicated server. (Originally a Go service; ported to Rust in the
> Go→Rust consolidation — see [02-architecture.md](02-architecture.md), ADR-7.)

## Why

One gateway sees its own traffic. A team runs *many* gateways — per service, per
region, per developer laptop. TokenFuse Cloud is the **single pane of glass**:
every gateway pushes its settled-call telemetry to one control plane, which rolls
it up per organization so you can see, across the whole fleet, which runs are
burning money and where.

The gateway stays the enforcement point (fast, local, fail-open). The Cloud is
an **optional** aggregation layer on top — turning it off changes nothing about
enforcement.

## Shape

```
 gateway A ─┐  POST /v1/ingest {records:[…]}   (Bearer org-key)
 gateway B ─┼──────────────────────────────▶  ┌──────────────────────┐
 gateway C ─┘                                  │  control plane (Rust)│
                                               │  org → run aggregates│
 browser ──── GET / (dashboard) ───────────▶  │  + embedded dashboard │
          ─── GET /v1/runs, /v1/summary ────▶  └──────────────────────┘
```

### Control plane (`crates/cloud`, Rust/axum, single static binary)

- **`POST /v1/ingest`** — a gateway pushes a batch of `CallRecord`s; the org is
  resolved from the `Authorization: Bearer <key>` header, which must be an
  **admin** credential (it is a write, and what it writes raises incidents and
  grades compliance controls).
- **`GET /v1/runs`** — the caller org's per-run aggregates (spend, calls, cache
  hits, steps, last-seen). `model` is the model of the run's latest call by
  that call's own timestamp; `models` lists every model its admitted calls
  named, each with `calls` and `spent_microusd` (at most 16 ids, the rest under
  `(other models)`), and `model_switches` counts how often an admitted call
  named a different model from the one before it (CLAUDE.md invariant 111).
- **`GET /v1/summary`** — org totals (runs, calls, spend).
- **`GET /`** — an embedded, dependency-free dashboard (vanilla JS; enter your
  org key, auto-refreshes every 3 s). Browsers may call the API only from the
  origins in `TOKENFUSE_CLOUD_CORS_ORIGINS` (loopback when unset, invariant 131).
- **`GET /healthz`**.

Storage is concurrency-safe, keyed `org → run`, and **durable**: set
`TOKENFUSE_CLOUD_DATA=<path>` and the store loads a JSON snapshot on startup and
autosaves every 2 s (atomic tmp+rename), so it survives a restart. A SQL/columnar
backend (Postgres/ClickHouse) for scale + retention is a drop-in behind the same
`Store` methods.

**Auth + RBAC.** Org API keys come from
`TOKENFUSE_CLOUD_KEYS="key:org[:role][:plan],…"` (the control plane holds each key by its SHA-256 digest, invariant 133). The optional role is `admin`
(default) or `viewer`. Reads (`/v1/runs`, `/v1/summary`, `/v1/kills`,
`/v1/budgets`, `/v1/alerts`) work for any valid key of the org; **writes**
(`POST …/kill`, `POST …/budget`, `POST /v1/findings`, `POST /v1/ingest`)
require `admin`: a viewer key gets `403`. A missing/unknown key gets `401`.
Keys never cross orgs.

Ingest sat in the read list until 2026-08-05, on the reasoning that telemetry
should never be lost over a credential. What that overlooked is that ingested
records are not inert: three carrying `budget_exceeded` raise a High incident
that is mailed to a human, and every record feeds the `decision_counts`
`/v1/compliance` grades controls from. A read-only role could therefore page
an operator and manufacture evidence. Note what this does NOT fix: there is
still no gateway-specific credential, so the plane cannot tell the real
gateway from any other holder of an admin org key, and records stay untrusted
input (see the `DISCLAIMER` in `tokenfuse_core::compliance`).

**Fails closed when unconfigured.** If `TOKENFUSE_CLOUD_KEYS` is unset, empty,
or every entry is malformed, the control plane starts with **no valid keys**,
so every request gets `401`. It does **not** fall back to a default credential.
There is no dev fallback credential any more: `TOKENFUSE_CLOUD_ALLOW_DEVKEY`
is still a recognised name, but a control plane started with it set refuses
to start and says why. Configure `TOKENFUSE_CLOUD_KEYS` instead, also for
local dev.

- **`GET /v1/alerts`** — runs that have spent ≥ a fraction of their central
  budget. Threshold defaults to `0.8`, overridable per-deploy with
  `TOKENFUSE_CLOUD_ALERT_PCT` or per-request with `?pct=` (0..1). The embedded
  dashboard surfaces the count and flags near-budget runs with a ⚠.

### Gateway side (`crates/gateway/src/cloudsink.rs`)

`CloudSink` is an `EventSink` that batches settled calls and POSTs them to the
control plane **asynchronously**: the request path never waits on the network. A
push the control plane cannot be reached for is queued in memory (10,000
records, oldest dropped first) and replayed in order when it answers again,
with one log line at the start of an outage and one at its end (invariant 53); a
push the control plane REFUSES is dropped and warned about once per status
(invariant 13). A gateway stopped with SIGTERM or SIGINT (`docker stop`, a
Kubernetes pod deletion) first stops taking calls, then delivers what it still
holds (the queue, then the calls answered since the last flush tick, after any
push already on the wire has been answered) within 5 s, and logs a warning with
the count of records the control plane did not receive if any are left
(invariant 112). A SIGKILL, an out-of-memory kill or a lost node still loses
whatever was not yet pushed, at most the last 2 s of calls plus the queue; the
local Parquet trace stays the source of truth. Every record carries the unit's `owner` from the identity map
beside its trace fields (invariant 54). A periodic flush ships telemetry
promptly even below the batch size, and is what retries the queue. It composes
with the other sinks via `TeeSink`.

At startup, a gateway with an identity map asks the same control plane for
`GET /v1/units` once, within five seconds, and seeds each unit's month-to-date
into its unit ledger before it listens, so a central monthly cap is enforced
against the month rather than against the tally since the last restart
(invariant 52). It reads each run's spend so far, the Cloud run budgets and the
Cloud kills the same way (invariants 70 and 103). A control plane it cannot reach
costs one warning, not a gap: the gateway starts, keeps asking in the background
(a quarter second, doubling, at most five), and until it has read all of it
answers a call carrying `x-fuse-run-id` with `503 seed_pending` (retryable,
`retry-after: 1`) in enforce, or forwards it marked `seed_pending` in
`x-fuse-would-block` in shadow and warn. Each run it touches that way is one
`dependency_failed` on the bus (`dependency: control_plane`, `stage: seed`).

Enable it on any gateway, with a key the control plane lists for that gateway
(`secret:org:ingest:site-name` in `TOKENFUSE_CLOUD_KEYS`; there is no built-in key):

```bash
TOKENFUSE_CLOUD_URL=http://control-plane:8080 \
TOKENFUSE_CLOUD_KEY="$INGEST_KEY" \
  tokenfuse
```

## Run the whole stack

Both images are published to GHCR, so nothing builds locally:

```bash
export TOKENFUSE_DEMO_ADMIN_KEY=$(openssl rand -hex 24)
export TOKENFUSE_DEMO_INGEST_KEY=$(openssl rand -hex 24)
cd cloud
docker compose up          # pulls ghcr.io/taipanbox/tokenfuse{,-control-plane}
```

Brings up the control plane (`:8080`, with the dashboard) and a gateway (`:4100`)
already wired to it, every port published on `127.0.0.1` only. Open
**http://localhost:8080**, enter your `TOKENFUSE_DEMO_ADMIN_KEY`, send traffic
through `:4100`, and watch runs + spend appear live. The gateway holds the ingest
key, which can push telemetry but cannot kill runs or set budgets.

Run the control plane on its own anywhere:

```bash
docker run -p 127.0.0.1:8080:8080 \
  -e TOKENFUSE_CLOUD_HOST=0.0.0.0 \
  -e TOKENFUSE_CLOUD_KEYS="$ADMIN_KEY:acme:admin" \
  ghcr.io/taipanbox/tokenfuse-control-plane
```

`TOKENFUSE_CLOUD_HOST=0.0.0.0` is needed in a container, where the default
loopback bind is the container's own and a published port finds nothing behind
it; publishing on `127.0.0.1` keeps the plane off the host's network.

## Verified end-to-end

Three managed calls through the gateway → the Cloud aggregated **3 runs / 3 calls
/ $0.0315**, per-run spend and last-seen correct; unauthenticated requests get
`401`. Control plane: `cargo test -p tokenfuse-cloud` (aggregation, org isolation, auth, RBAC, alerts, persistence, dashboard).

## Kill from the cloud (implemented)

The dashboard has a **Kill** button per run. It calls `POST /v1/runs/{run}/kill`
on the control plane, which records the kill per org. Every gateway of that org
runs a **kill poller** (`cloudsink::spawn_kill_poller`) that fetches
`GET /v1/kills` every few seconds and applies each id to its local kill set —
so the run is hard-stopped (`402 killed`) across the whole fleet, not just on one
gateway. Enabled automatically whenever `TOKENFUSE_CLOUD_URL` + `_KEY` are set.

A kill made on one gateway's own `POST /v1/runs/{id}/kill` stays on that
gateway: it is not sent to the Cloud's kill list, so no other gateway applies
it. What the Cloud does learn is the gateway's refusal: a call refused as
`killed` is a trace row like any other, and the run's row in `GET /v1/runs`
then reads `killed: true` (and `killed_by_gateway: true`), so the fleet view
and anything reading it show the run as killed. The run is not added to
`GET /v1/kills`. A run killed locally that makes no further call never reaches
the Cloud as killed (invariant 111).

## Central budgets (implemented)

Set a run's budget from the Cloud and every gateway of the org enforces it,
overriding the client-supplied `x-fuse-budget-usd` header. The dashboard has a
per-run **Budget** button (`POST /v1/runs/{run}/budget {budget_usd}`); gateways
run a **budget poller** (`cloudsink::spawn_budget_poller`) that fetches
`GET /v1/budgets` and applies the overrides. So an operator can tighten (or
raise) a runaway run's cap centrally without touching the agent.

A Cloud budget is the operator's own word, so the gateway's
`TOKENFUSE_MAX_RUN_BUDGET_USD` ceiling (which bounds what a caller may declare
for itself) never clamps one: a run budgeted here above that ceiling keeps the
budget set here.

## Two dashboards

- **Embedded** (`GET /` on the control plane) — dependency-free vanilla JS, zero
  extra deploy. Good for a quick look.
- **Next.js app** (`cloud/dashboard`, App Router, TypeScript, static export) —
  the richer UI: summary cards, a spend-by-run chart, the runs table with kill +
  budget actions, auto-refresh. Talks to the control plane's API from the
  browser (a base-URL + org-key connect form). The control plane answers a
  browser only from the origins it names: loopback by default, and any other
  dashboard origin (a hosted one, another machine) must be listed in
  `TOKENFUSE_CLOUD_CORS_ORIGINS=https://dash.example.com,...` (exact origins;
  an entry that is not one stops the control plane at startup). Open the
  dashboard with its key in the URL fragment, `…/#key=<org-key>`: a fragment is
  never sent to any server, and the page removes it from the address bar once it
  has read it (invariant 133). A `?key=` query still works for old links. Built
  to static files and served by nginx — published as
  `ghcr.io/taipanbox/tokenfuse-dashboard` and wired into `docker compose` on
  `:3000`.

## Not yet (follow-ups)
- **SQL/columnar store** (Postgres/ClickHouse) for scale + retention (today: durable JSON snapshot).
- **Auth hardening** — per-org key rotation, rate limits (RBAC and budget alerts
  are implemented; run behind a TLS-terminating proxy in production).
