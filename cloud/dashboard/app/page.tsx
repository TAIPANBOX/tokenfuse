"use client";

import { useCallback, useEffect, useState } from "react";

type Run = {
  run_id: string;
  model: string;
  spent_microusd: number;
  calls: number;
  cache_hits: number;
  steps: number;
  last_seen_millis: number;
  killed: boolean;
  // Tool calls the model emitted across this run's calls (I1, docs/21-tool-runs.md).
  tool_calls: number;
  // The human this run is answerable to (RunAgg.owner, #295/#310): the
  // unit's configured owner, else the delegation chain's root user://
  // principal. "" is the ordinary case, a run nobody delegated - never
  // rendered blank. Optional because a Cloud older than #310 omits the key
  // entirely rather than sending "".
  owner?: string;
  // The site (gateway) that pushed this run's calls, from the pushing key's
  // bound site (invariant 65) - never anything the run's own records could
  // claim. "" is the ordinary case, a run pushed by an unbound key. Optional
  // because a Cloud older than invariant 65 omits the key entirely.
  site?: string;
  // Invariant 86. Calls the gateway refused on this run, and the decision of
  // its latest call ("allow", "cache_hit" or a Breaker reason such as
  // "identity_mismatch"). Optional: a Cloud older than v1.8.0 omits them,
  // and the Status column then falls back to what it always showed.
  blocked?: number;
  last_decision?: string;
  // Admitted calls the gateway charged at the fallback rate (the price book
  // had no row for the model id), and admitted calls whose gateway named no
  // price basis at all (older than v1.8.0, so possibly the fallback too).
  fallback_calls?: number;
  basis_unreported_calls?: number;
};
type ModelCalls = { model: string; calls: number };
type Summary = {
  runs: number;
  calls: number;
  spent_microusd: number;
  tool_calls: number;
  // Invariant 86, exact over the org's whole ingest history. Absent on a
  // Cloud older than v1.8.0, where the fallback tile then says so.
  fallback_calls?: number;
  basis_unreported_calls?: number;
  fallback_models?: ModelCalls[];
};
type Bucket = { t: number; cost_microusd: number; calls: number; blocked: number };
type Alert = {
  run_id: string;
  spent_microusd: number;
  budget_micros: number;
  fraction: number;
  killed: boolean;
};
type Savings = {
  blocked_spend_microusd: number;
  cache_saved_microusd: number;
  budget_breaks: number;
  total_saved_microusd: number;
};
// Per-business-unit spend rollup (docs/20 identity map). Unmapped spend rolls
// up under the literal id "unassigned". The month_* fields cover the current
// UTC calendar month - the same window the "$X/mo" caps in /v1/unit-budgets
// are enforced against by the gateway. They are absent on a plane that
// predates the month-to-date fold: the card then falls back to the all-time
// total, honestly labeled, never silently passed off as a month.
type Unit = {
  unit: string;
  spent_microusd: number;
  calls: number;
  runs: number;
  last_seen_millis: number;
  month?: string;
  month_spent_microusd?: number;
  month_calls?: number;
};
// Per-owner spend rollup (GET /v1/owners, OwnerAgg): the human a run is
// answerable to, folded across every unit and agent acting on their behalf.
// The literal id "unassigned" is the server's own fold for a run whose chain
// named no human - never a blank string.
type Owner = {
  owner: string;
  spent_microusd: number;
  calls: number;
  runs: number;
  agents: number;
  last_seen_millis: number;
  tool_calls: number;
};
// Per-site (gateway) ingest rollup (GET /v1/gateways, GatewayAgg, invariant
// 65): which site pushed, how much, and when this plane last heard from it.
// The literal id "unnamed" is the server's own fold for a push from a key
// bound to no site - never a blank string. last_push_millis is the plane's
// OWN clock at the moment of the push (the figure "has this site gone
// silent" reads); last_record_millis is only the newest call TIMESTAMP the
// site has ever reported, descriptive and never used for liveness.
type Gateway = {
  site: string;
  spent_microusd: number;
  calls: number;
  tool_calls: number;
  pushes: number;
  first_push_millis: number;
  last_push_millis: number;
  last_record_millis: number;
};
// One detector finding (GET /v1/incidents, Incident). severity is always one
// of these five wire strings (tokenfuse_core::Severity, lowercased).
// run_id/agent_id are absent for an org-scoped detector (spend_spike).
// summary is the Cloud's own sentence when it has one (mostly external
// findings); TokenFuse's own detectors are described by `kind` alone.
type Incident = {
  id: string;
  run_id: string | null;
  agent_id: string | null;
  kind: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  first_seen_millis: number;
  last_seen_millis: number;
  occurrences: number;
  acknowledged: boolean;
  source?: string | null;
  summary?: string | null;
};

const usd = (micro: number) => "$" + (micro / 1e6).toFixed(2);

// A run's latest call was refused when its decision is anything but the two
// admitted outcomes. The Cloud only reports decisions it trusts (invariant
// 83), so this never shows a string a caller made up.
const isRefusal = (d?: string) => !!d && d !== "allow" && d !== "cache_hit";

// Breaker reason -> a short label for the Status pill; the raw wire string
// stays in the tooltip. A reason this dashboard does not know the words for
// shows as itself, which is honest rather than a guess.
const REFUSAL_LABELS: Record<string, string> = {
  budget_exceeded: "budget",
  policy_violation: "policy",
  loop_detected: "loop",
  killed: "killed",
  wasm_policy: "policy",
  taint_blocked: "taint",
  dlp_blocked: "dlp",
  unit_budget_exceeded: "unit cap",
  identity_mismatch: "identity",
};
const refusalLabel = (d: string) => REFUSAL_LABELS[d] || d;

// Detector kind -> a readable label. Falls back to the raw wire string for a
// kind this dashboard does not yet know the words for, which is honest
// (the Cloud's own wording) rather than a guess.
const INCIDENT_LABELS: Record<string, string> = {
  budget_exhausted: "Budget exhausted",
  sustained_loop: "Sustained loop",
  spend_spike: "Spend spike",
  fanout_explosion: "Fan-out explosion",
  budget_threshold: "Near budget",
  run_stalled: "Run stalled",
};
const incidentLabel = (kind: string) => INCIDENT_LABELS[kind] || kind;

// A site with no push in this long reads as "silent" on the Gateways card
// (invariant 65: nothing pages anybody when this happens, so the label is
// the only signal a human gets).
const SILENT_AFTER_MS = 5 * 60 * 1000;

function ago(ms: number): string {
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 60) return s + "s ago";
  const m = Math.round(s / 60);
  if (m < 60) return m + "m ago";
  const h = Math.round(m / 60);
  if (h < 24) return h + "h ago";
  return Math.round(h / 24) + "d ago";
}

function sevClass(s: Incident["severity"]): string {
  if (s === "critical" || s === "high") return "high";
  if (s === "medium") return "medium";
  return "low";
}

function heatClass(frac: number, killed: boolean): "mint" | "amber" | "ember" {
  if (killed) return "mint";
  if (frac >= 1) return "ember";
  if (frac >= 0.8) return "amber";
  return "mint";
}

function planeHost(base: string): string {
  try {
    return new URL(base).host;
  } catch {
    return "plane";
  }
}

function Sparkline({ buckets }: { buckets: Bucket[] }) {
  const vals = buckets.map((b) => b.cost_microusd);
  if (vals.length < 2) return null;
  const max = Math.max(1, ...vals);
  const W = 600;
  const H = 100;
  // Refused calls per bucket (Bucket.blocked, which /v1/series has always
  // served and this chart never drew), as bars along the floor in the
  // refusal colour, scaled on their own so one refusal is still visible
  // beside a large spend line. Invariant 86.
  const maxBlocked = Math.max(0, ...buckets.map((b) => b.blocked || 0));
  const barW = Math.max(2, W / buckets.length - 2);
  const pts = vals
    .map((v, i) => {
      const x = (i / (vals.length - 1)) * W;
      const y = H - (v / max) * (H - 10) - 5;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const lastX = W;
  const lastY = H - (vals[vals.length - 1] / max) * (H - 10) - 5;
  return (
    <svg className="spark" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <polygon points={`0,${H} ${pts} ${W},${H}`} fill="rgba(244,178,62,0.22)" />
      <polyline points={pts} fill="none" stroke="#f4b23e" strokeWidth="2.5" vectorEffect="non-scaling-stroke" />
      <circle cx={lastX} cy={lastY} r="3.5" fill="#ff574b" />
      {maxBlocked > 0 &&
        buckets.map((b, i) =>
          b.blocked > 0 ? (
            <rect
              key={i}
              x={(i / (buckets.length - 1)) * W - barW / 2}
              y={H - (b.blocked / maxBlocked) * 28}
              width={barW}
              height={(b.blocked / maxBlocked) * 28}
              fill="rgba(255,87,75,0.55)"
            >
              <title>{b.blocked} refused</title>
            </rect>
          ) : null,
        )}
    </svg>
  );
}

export default function Page() {
  const [base, setBase] = useState("");
  const [key, setKey] = useState("");
  const [connected, setConnected] = useState(false);
  const [runs, setRuns] = useState<Run[]>([]);
  const [summary, setSummary] = useState<Summary>({ runs: 0, calls: 0, spent_microusd: 0, tool_calls: 0 });
  const [budgets, setBudgets] = useState<Record<string, number>>({});
  const [units, setUnits] = useState<Unit[]>([]);
  const [unitBudgets, setUnitBudgets] = useState<Record<string, number>>({});
  const [series, setSeries] = useState<Bucket[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [savings, setSavings] = useState<Savings | null>(null);
  const [owners, setOwners] = useState<Owner[]>([]);
  // null means "not available on this plane" (unreachable or older Cloud),
  // distinct from an empty array meaning "fetched, no incidents open".
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  // Same null-vs-empty rule as incidents above: null is "not available on
  // this plane", [] is "reachable, nobody has pushed yet".
  const [gateways, setGateways] = useState<Gateway[] | null>(null);
  const [status, setStatus] = useState("");
  const [armed, setArmed] = useState<string | null>(null);

  useEffect(() => {
    // URL params (?base=&key=) let you connect via a shareable link; they take
    // precedence over the last-used values persisted in localStorage.
    const q = new URLSearchParams(window.location.search);
    const b = q.get("base") || localStorage.getItem("tf_base") || "http://localhost:8080";
    const k = q.get("key") || localStorage.getItem("tf_key") || "";
    setBase(b);
    setKey(k);
    if (k) {
      localStorage.setItem("tf_base", b);
      localStorage.setItem("tf_key", k);
      setConnected(true);
    }
  }, []);

  const api = useCallback(
    async (path: string, init?: RequestInit) => {
      const r = await fetch(base.replace(/\/$/, "") + path, {
        ...init,
        headers: { Authorization: "Bearer " + key, ...(init?.headers || {}) },
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r;
    },
    [base, key],
  );

  const refresh = useCallback(async () => {
    if (!connected || !key) return;
    try {
      const [runsRes, sumRes, budRes, serRes, alertRes, sav, unitsRes, unitBud, own, inc, gws] =
        await Promise.all([
          api("/v1/runs"),
          api("/v1/summary"),
          api("/v1/budgets"),
          api("/v1/series?window=15m&step=60s"),
          api("/v1/alerts"),
          // Savings can be absent on an older plane, exactly like /v1/units
          // below. Swallow the error so the rest of the dashboard still
          // refreshes; the tile hides. This used to say "a paid-plan feature:
          // 402 on free plans", which stopped being true when plan entitlements
          // were removed from the product (#123, #125): there are no plans, so
          // there is no 402 to catch, and the only reason left to be defensive
          // here is a plane that predates the endpoint.
          api("/v1/savings")
            .then((r) => r.json() as Promise<Savings>)
            .catch(() => null),
          // Units + their monthly caps (docs/20). Absent on an older plane that
          // predates the identity map: swallow so the rest still refreshes and
          // the Business units card simply shows nothing.
          api("/v1/units")
            .then((r) => r.json() as Promise<Unit[]>)
            .catch(() => [] as Unit[]),
          api("/v1/unit-budgets")
            .then((r) => r.json() as Promise<Record<string, number>>)
            .catch(() => ({}) as Record<string, number>),
          // Owners (GET /v1/owners, OwnerAgg): same graceful-absence rule as
          // /v1/units above - an older plane simply shows no owner rollup.
          api("/v1/owners")
            .then((r) => r.json() as Promise<Owner[]>)
            .catch(() => [] as Owner[]),
          // Incidents (GET /v1/incidents): unlike the fetches above, a failure
          // here is kept visible rather than swallowed into an empty list -
          // an unreachable or older plane must read as "not available", never
          // as the false-positive "no incidents open".
          api("/v1/incidents")
            .then((r) => r.json() as Promise<Incident[]>)
            .catch(() => null),
          // Gateways (GET /v1/gateways, GatewayAgg, invariant 65): same
          // absent-vs-empty rule as incidents above - a plane that cannot be
          // reached, or predates this endpoint, must read as "not
          // available", never as the false-positive "no gateways pushed".
          api("/v1/gateways")
            .then((r) => r.json() as Promise<Gateway[]>)
            .catch(() => null),
        ]);
      const rs: Run[] = await runsRes.json();
      const bud: Record<string, number> = await budRes.json();
      rs.sort((a, b) => {
        const fa = bud[a.run_id] ? a.spent_microusd / bud[a.run_id] : 0;
        const fb = bud[b.run_id] ? b.spent_microusd / bud[b.run_id] : 0;
        return fb - fa || b.spent_microusd - a.spent_microusd;
      });
      setRuns(rs);
      setBudgets(bud);
      setUnits(unitsRes);
      setUnitBudgets(unitBud);
      setOwners(own);
      setIncidents(inc);
      setGateways(gws);
      setSummary(await sumRes.json());
      setSeries(await serRes.json());
      setAlerts(await alertRes.json());
      setSavings(sav);
      setStatus("live");
    } catch (e) {
      setStatus("error: " + (e as Error).message);
    }
  }, [api, connected, key]);

  useEffect(() => {
    if (!connected) return;
    refresh();
    const t = setInterval(refresh, 3000);
    return () => clearInterval(t);
  }, [connected, refresh]);

  const connect = () => {
    localStorage.setItem("tf_base", base);
    localStorage.setItem("tf_key", key);
    setConnected(true);
  };
  const disconnect = () => {
    localStorage.removeItem("tf_key");
    setConnected(false);
  };

  const kill = async (run: string) => {
    if (armed !== run) {
      setArmed(run);
      setTimeout(() => setArmed((a) => (a === run ? null : a)), 2500);
      return;
    }
    setArmed(null);
    try {
      await api(`/v1/runs/${encodeURIComponent(run)}/kill`, { method: "POST" });
      refresh();
    } catch (e) {
      setStatus("kill failed: " + (e as Error).message);
    }
  };

  const setBudget = async (run: string) => {
    const v = prompt(`Set budget for run '${run}' (USD):`);
    if (v === null) return;
    const n = parseFloat(v);
    if (isNaN(n)) return;
    try {
      await api(`/v1/runs/${encodeURIComponent(run)}/budget`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ budget_usd: n }),
      });
      refresh();
    } catch (e) {
      setStatus("set budget failed: " + (e as Error).message);
    }
  };

  // A unit's monthly cap (docs/20). The "unassigned" bucket is spend the map
  // did not attribute; it has no cap to set, so its Budget button is hidden.
  const setUnitBudget = async (unit: string) => {
    const v = prompt(`Set monthly budget for unit '${unit}' (USD):`);
    if (v === null) return;
    const n = parseFloat(v);
    if (isNaN(n)) return;
    try {
      await api(`/v1/units/${encodeURIComponent(unit)}/budget`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ budget_usd: n }),
      });
      refresh();
    } catch (e) {
      setStatus("set unit budget failed: " + (e as Error).message);
    }
  };

  const caps = Object.values(budgets).reduce((a, b) => a + b, 0);
  const fleetFrac = caps > 0 ? summary.spent_microusd / caps : 0;
  const lastBurn = [...series].reverse().find((b) => b.cost_microusd > 0);
  const fleetRate = lastBurn ? lastBurn.cost_microusd / 1e6 : 0;
  const maxSpend = Math.max(1, ...runs.map((r) => r.spent_microusd));
  const activeRuns = runs.filter((r) => !r.killed).length;
  const killedRuns = runs.filter((r) => r.killed).length;

  const brand = (
    <div className="brand">
      <svg width="30" height="30" viewBox="0 0 34 34" fill="none" aria-hidden>
        <rect x="1" y="1" width="32" height="32" rx="9" fill="url(#g)" />
        <g transform="translate(17 17) scale(0.92) translate(-11 -12)">
          <path d="M13 2 4 14h6l-1 8 9-12h-6z" fill="none" stroke="#0A0E13"
            strokeWidth="2.4" strokeLinejoin="round" strokeLinecap="round" />
        </g>
        <defs>
          <linearGradient id="g" x1="2" y1="2" x2="32" y2="32" gradientUnits="userSpaceOnUse">
            <stop stopColor="#F6B740" />
            <stop offset="1" stopColor="#FF574B" />
          </linearGradient>
        </defs>
      </svg>
      <div className="w">
        TokenFuse <span>Cloud</span>
      </div>
      <div className="tagm">enforcement, not observability</div>
    </div>
  );

  return (
    <div className="shell">
      <header className="topbar">
        {brand}
        {connected && (
          <div className="conn">
            <span className="chip">
              <span className="k" />
              plane <b>{planeHost(base)}</b> ·{" "}
              <span className={status.startsWith("error") ? "err" : "live"}>
                {status.startsWith("error") ? status : "live · 3s"}
              </span>
            </span>
            <button className="mini" onClick={disconnect}>
              Disconnect
            </button>
          </div>
        )}
      </header>

      {!connected ? (
        <div className="card connect-panel">
          <h2>Connect a control plane</h2>
          <p className="sub">Point the dashboard at a TokenFuse Cloud plane with an org key.</p>
          <div className="row">
            <div>
              <div className="lbl">Plane URL</div>
              <input
                className="field"
                style={{ width: "100%", marginTop: 6 }}
                value={base}
                onChange={(e) => setBase(e.target.value)}
                placeholder="https://…"
              />
            </div>
            <div>
              <div className="lbl">Org key</div>
              <input
                className="field"
                style={{ width: "100%", marginTop: 6 }}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="devkey"
              />
            </div>
            <button className="iris" onClick={connect} style={{ marginTop: 4 }}>
              Connect
            </button>
          </div>
        </div>
      ) : (
        <>
          <div className="ammeter">
            <span className="lab">Fleet draw</span>
            <div className={"fuse " + heatClass(fleetFrac, false)}>
              <i style={{ width: `${Math.min(100, fleetFrac * 100)}%` }} />
            </div>
            <span className="rd">
              spending <b>{usd(summary.spent_microusd)}</b> of <b>{usd(caps)}</b> caps ·{" "}
              <b style={{ color: "var(--amber)" }}>{Math.round(fleetFrac * 100)}%</b>
            </span>
          </div>

          <div className="heroband">
            <div className="card hero">
              <div className="cap">Fleet burn rate · all gateways</div>
              <div className="rate">
                <span className="v">{fleetRate.toFixed(2)}</span>
                <span className="u">$/min</span>
                <span className="spent">spent {usd(summary.spent_microusd)}</span>
              </div>
              <Sparkline buckets={series} />
              {series.some((b) => b.blocked > 0) && (
                <div className="refusedlegend">
                  <i /> refused calls ·{" "}
                  {series.reduce((a, b) => a + (b.blocked || 0), 0)} in the last 15 min
                </div>
              )}
              {caps > 0 && (
                <>
                  <div className={"fuse " + heatClass(fleetFrac, false)}>
                    <i style={{ width: `${Math.min(100, fleetFrac * 100)}%` }} />
                  </div>
                  <div className="agl">
                    <span>
                      spent <b>{usd(summary.spent_microusd)}</b>
                    </span>
                    <span>
                      caps <b>{usd(caps)}</b> · {Math.round(fleetFrac * 100)}%
                    </span>
                  </div>
                </>
              )}
            </div>
            <div className="tiles">
              {/* `activeRuns` is a live count of retained, non-killed runs -
                  genuinely "now". Everything read off `summary.*`, though, is
                  `Store::summary`'s org-wide running total: exact over the
                  FULL ingest history, persisted across restarts, with no
                  day-boundary reset - so those labels must say "all time",
                  never "today". Don't rebuild "today" by summing /v1/series
                  over a 24h window client-side either: the series is an
                  in-memory sample log (SERIES_CAP-bounded, gone on plane
                  restart), so that sum silently undercounts. A real daily
                  figure needs a day-windowed rollup on the plane first. */}
              <div className="card tile">
                <div className="k">Active runs</div>
                <div className="n">{activeRuns}</div>
                <div className="s">{summary.calls} calls · all time</div>
              </div>
              <div className="card tile">
                <div className="k">Spent</div>
                <div className="n">{usd(summary.spent_microusd)}</div>
                <div className="s">all time · reserve → settle</div>
              </div>
              <div className="card tile alert">
                <div className="k">Alerts</div>
                <div className="n">{alerts.length}</div>
                <div className="s">≥ 80% of cap</div>
              </div>
              <div className="card tile killed">
                <div className="k">Killed</div>
                <div className="n">{killedRuns}</div>
                <div className="s">this org</div>
              </div>
              {/* `summary.tool_calls` (like `summary.spent_microusd` in the
                  "Spent" tile above, and `summary.calls` in "Active runs")
                  is `Store::summary`'s org-wide, full-ingest-history running
                  total - there is no day-boundary reset anywhere in
                  `OrgTotals`. Those tiles say "all time" for exactly this
                  reason (#131, and see the caveat there about why a client-
                  side /v1/series sum is not an honest "today"), so this one
                  does too: "Tool runs", never "...today". */}
              <div className="card tile" style={{ gridColumn: "1 / -1" }}>
                <div className="k">Tool runs</div>
                <div className="n">{summary.tool_calls}</div>
                <div className="s">all time - observed only</div>
              </div>
              {/* Invariant 86: spend charged at the fallback rate, the
                  conservative 15 / 75 USD per million tokens a gateway
                  charges a model id its price book has no row for (up to
                  five times a list price). All time, like the tiles above.
                  A Cloud older than v1.8.0 does not report it, and the tile
                  then says nothing rather than a zero that reads as clean. */}
              {summary.fallback_calls !== undefined && (
                <div className="card tile" style={{ gridColumn: "1 / -1" }}>
                  <div className="k">Fallback-priced</div>
                  <div
                    className="n"
                    style={summary.fallback_calls ? { color: "var(--amber)" } : undefined}
                  >
                    {summary.fallback_calls}
                  </div>
                  <div className="s">
                    {summary.fallback_calls === 0
                      ? "calls charged at the fallback rate · all time"
                      : "calls charged at the fallback rate · " +
                        (summary.fallback_models || [])
                          .slice(0, 3)
                          .map((m) => `${m.model} ×${m.calls}`)
                          .join(" · ")}
                    {(summary.basis_unreported_calls || 0) > 0 &&
                      ` · ${summary.basis_unreported_calls} from gateways that name no basis`}
                  </div>
                </div>
              )}
              {savings && (
                <div className="card tile" style={{ gridColumn: "1 / -1" }}>
                  {/* SavingsAcc is the same all-time shape: a persisted,
                      monotonic accumulator with no month reset - hence
                      "all time", not the "this month" it used to claim. */}
                  <div className="k">Saved</div>
                  <div
                    className="n"
                    style={savings.total_saved_microusd ? { color: "var(--mint)" } : undefined}
                  >
                    {usd(savings.total_saved_microusd)}
                  </div>
                  <div className="s">
                    all time · blocked {usd(savings.blocked_spend_microusd)} · cache {usd(savings.cache_saved_microusd)}
                    {savings.budget_breaks > 0 && ` · ${savings.budget_breaks} budget breaks`}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div className="main">
            <div className="card">
              <div className="sechead">
                <div className="t">Runs</div>
                <div className="r">sorted · burn</div>
              </div>
              <div className="tablewrap">
                <table>
                  <thead>
                    <tr>
                      <th>Run</th>
                      <th>Model</th>
                      <th>Owner</th>
                      <th>Site</th>
                      <th>Spent / cap</th>
                      <th className="num">Calls</th>
                      <th className="num">Steps</th>
                      <th className="num">Tool runs</th>
                      <th>Status</th>
                      <th className="num">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((r) => {
                      const budget = budgets[r.run_id] || 0;
                      const frac = budget > 0 ? r.spent_microusd / budget : 0;
                      const heat = heatClass(frac, r.killed);
                      const over = !r.killed && budget > 0 && frac >= 1;
                      return (
                        <tr key={r.run_id} className={over ? "over" : r.killed ? "killedrow" : ""}>
                          <td>
                            <span className="rid">{r.run_id}</span>
                          </td>
                          <td>
                            <span className="rmodel">{r.model || "—"}</span>
                            {(r.fallback_calls || 0) > 0 && (
                              <>
                                {" "}
                                <span
                                  className="pill near"
                                  title={`${r.fallback_calls} call(s) charged at the fallback rate: the price book has no row for this model id`}
                                >
                                  fallback
                                </span>
                              </>
                            )}
                          </td>
                          <td>
                            <span
                              className="rmodel"
                              style={!r.owner ? { color: "var(--faint)" } : undefined}
                            >
                              {r.owner || "not reported"}
                            </span>
                          </td>
                          <td>
                            <span
                              className="rmodel"
                              style={!r.site ? { color: "var(--faint)" } : undefined}
                            >
                              {r.site || "not named"}
                            </span>
                          </td>
                          <td className="spentcell">
                            {budget > 0 ? (
                              <>
                                <div className="nrow">
                                  <b style={over ? { color: "var(--ember)" } : undefined}>{usd(r.spent_microusd)}</b>
                                  <span style={{ color: "var(--dim)" }}>{usd(budget)}</span>
                                </div>
                                <div className={"fuse " + heat}>
                                  <i style={{ width: `${Math.min(100, frac * 100)}%` }} />
                                </div>
                              </>
                            ) : (
                              <>
                                <div className="nrow">
                                  <b>{usd(r.spent_microusd)}</b>
                                </div>
                                <div className="nocap">no cap set</div>
                              </>
                            )}
                          </td>
                          <td className="num">
                            {r.calls}
                            {(r.blocked || 0) > 0 && (
                              <div className="refused">{r.blocked} refused</div>
                            )}
                          </td>
                          <td className="num">{r.steps}</td>
                          <td className="num">{r.tool_calls}</td>
                          <td>
                            {r.killed ? (
                              <span className="pill dead">killed</span>
                            ) : isRefusal(r.last_decision) ? (
                              <span
                                className="pill crit"
                                title={`latest call refused: ${r.last_decision}`}
                              >
                                refused · {refusalLabel(r.last_decision!)}
                              </span>
                            ) : budget > 0 && frac >= 1 ? (
                              <span className="pill crit">over cap</span>
                            ) : budget > 0 && frac >= 0.8 ? (
                              <span className="pill near">near cap</span>
                            ) : (
                              <span className="pill live">live</span>
                            )}
                          </td>
                          <td>
                            <div className="acts">
                              <button className="mini" onClick={() => setBudget(r.run_id)}>
                                Budget
                              </button>
                              {r.killed ? (
                                <span className="pill dead">402 killed</span>
                              ) : (
                                <button
                                  className={"mini kill" + (armed === r.run_id ? " armed" : "")}
                                  onClick={() => kill(r.run_id)}
                                >
                                  {armed === r.run_id ? "Confirm" : "Kill"}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {runs.length === 0 && (
                <div className="empty">No runs yet — send traffic through a gateway.</div>
              )}
            </div>

            <div className="rail">
              <div className="card">
                <div className="sechead">
                  <div className="t">Incidents</div>
                  <div className="r">detector findings</div>
                </div>
                {/* Distinct from Alerts below: an alert is this dashboard's own
                    live budget-fraction read of /v1/runs, computed here.
                    An incident is the Cloud's own detector finding
                    (/v1/incidents) - a budget block count, a loop repeat, a
                    run gone quiet (run_stalled, invariant 60) and so on.
                    incidents === null means the endpoint could not be read
                    (unreachable plane, or one old enough to lack it): that is
                    never shown as "none open", which would read as measured
                    when nothing was. */}
                {incidents === null ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    Not available on this plane.
                  </div>
                ) : incidents.length === 0 ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    No incidents open.
                  </div>
                ) : (
                  incidents
                    .slice()
                    .sort((a, b) => b.last_seen_millis - a.last_seen_millis)
                    .map((inc) => (
                      <div className="arow" key={inc.id}>
                        <span className={"d " + sevClass(inc.severity)} />
                        <div className="tx">
                          <div className="m">
                            {incidentLabel(inc.kind)}
                            {inc.run_id ? (
                              <>
                                {" "}
                                · run <span className="id">{inc.run_id}</span>
                              </>
                            ) : (
                              " · org-wide"
                            )}
                          </div>
                          <div className="s">
                            {inc.summary || (inc.agent_id ? `agent ${inc.agent_id}` : "unattributed")}
                            {inc.occurrences > 1 ? ` · x${inc.occurrences}` : ""}
                          </div>
                        </div>
                        <span
                          className="pct"
                          style={{
                            color:
                              inc.severity === "critical" || inc.severity === "high"
                                ? "var(--ember)"
                                : inc.severity === "medium"
                                  ? "var(--amber)"
                                  : "var(--dim)",
                          }}
                        >
                          {ago(inc.last_seen_millis)}
                        </span>
                      </div>
                    ))
                )}
              </div>

              <div className="card">
                <div className="sechead">
                  <div className="t">Alerts</div>
                  <div className="r">≥ 80% of cap</div>
                </div>
                {alerts.length === 0 ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    Nothing near cap.
                  </div>
                ) : (
                  alerts
                    .sort((a, b) => b.fraction - a.fraction)
                    .map((a) => (
                      <div className="arow" key={a.run_id}>
                        <span className={"d " + (a.fraction >= 1 ? "crit" : "near")} />
                        <div className="tx">
                          <div className="m">
                            Run <span className="id">{a.run_id}</span> {a.fraction >= 1 ? "over cap" : "near cap"}
                          </div>
                          <div className="s">
                            {usd(a.spent_microusd)} / {usd(a.budget_micros)}
                          </div>
                        </div>
                        <span className="pct" style={{ color: a.fraction >= 1 ? "var(--ember)" : "var(--amber)" }}>
                          {Math.round(a.fraction * 100)}%
                        </span>
                      </div>
                    ))
                )}
              </div>

              <div className="card">
                <div className="sechead">
                  <div className="t">Business units</div>
                  <div className="r">monthly caps</div>
                </div>
                {units.length === 0 ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    No units yet. Map keys and agents to units (docs/20), then send traffic.
                  </div>
                ) : (
                  <div className="tablewrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Unit</th>
                          <th>Spent / cap</th>
                          <th className="num">Runs</th>
                          <th className="num">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {units.map((u) => {
                          const cap = unitBudgets[u.unit] || 0;
                          // The caps are MONTHLY (enforced by the gateway over
                          // the UTC calendar month), so the bar must compare
                          // month-to-date spend - never the all-time total.
                          // An older plane omits month_spent_microusd: fall
                          // back to all-time with an explicit label rather
                          // than quietly over-reporting (the same honesty
                          // rule as the "all time" summary tiles).
                          const hasMonth = u.month_spent_microusd !== undefined;
                          const spent = u.month_spent_microusd ?? u.spent_microusd;
                          const frac = cap > 0 ? spent / cap : 0;
                          const heat = heatClass(frac, false);
                          const over = cap > 0 && frac >= 1;
                          const unassigned = u.unit === "unassigned";
                          return (
                            <tr key={u.unit} className={over ? "over" : ""}>
                              <td>
                                <span className="rid" style={unassigned ? { color: "var(--dim)" } : undefined}>
                                  {u.unit}
                                </span>
                              </td>
                              <td className="spentcell">
                                {cap > 0 ? (
                                  <>
                                    <div className="nrow">
                                      <b style={over ? { color: "var(--ember)" } : undefined}>{usd(spent)}</b>
                                      <span style={{ color: "var(--dim)" }}>{usd(cap)}/mo</span>
                                    </div>
                                    <div className={"fuse " + heat}>
                                      <i style={{ width: `${Math.min(100, frac * 100)}%` }} />
                                    </div>
                                    <div className="nocap">
                                      {hasMonth ? `this month · all time ${usd(u.spent_microusd)}` : "all time vs monthly cap"}
                                    </div>
                                  </>
                                ) : (
                                  <>
                                    <div className="nrow">
                                      <b>{usd(spent)}</b>
                                    </div>
                                    <div className="nocap">{hasMonth ? "this month · no cap set" : "all time · no cap set"}</div>
                                  </>
                                )}
                              </td>
                              <td className="num">{u.runs}</td>
                              <td>
                                <div className="acts">
                                  {unassigned ? (
                                    <span className="pill" style={{ color: "var(--dim)" }}>
                                      unmapped
                                    </span>
                                  ) : (
                                    <button className="mini" onClick={() => setUnitBudget(u.unit)}>
                                      Budget
                                    </button>
                                  )}
                                </div>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card">
                <div className="sechead">
                  <div className="t">Owners</div>
                  <div className="r">by human</div>
                </div>
                {owners.length === 0 ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    No owners yet. Map units to owners (docs/20), then send traffic.
                  </div>
                ) : (
                  <div className="tablewrap">
                    <table className="narrow">
                      <thead>
                        <tr>
                          <th>Owner</th>
                          <th>Spent</th>
                        </tr>
                      </thead>
                      <tbody>
                        {owners
                          .slice()
                          .sort((a, b) => b.spent_microusd - a.spent_microusd)
                          .map((o) => {
                            const unassigned = o.owner === "unassigned";
                            return (
                              <tr key={o.owner}>
                                <td>
                                  <span
                                    className="rid"
                                    style={unassigned ? { color: "var(--dim)" } : undefined}
                                  >
                                    {o.owner || "not reported"}
                                  </span>
                                </td>
                                {/* Two columns, not four: this card sits in the
                                    narrow rail, and separate Runs/Agents columns
                                    pushed the spend itself past the card's edge.
                                    The counts ride under the sum, the Business
                                    units card's own nrow/nocap shape. */}
                                <td className="spentcell">
                                  <div className="nrow">
                                    <b>{usd(o.spent_microusd)}</b>
                                  </div>
                                  <div className="nocap">
                                    {o.runs} {o.runs === 1 ? "run" : "runs"} · {o.agents}{" "}
                                    {o.agents === 1 ? "agent" : "agents"}
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card">
                <div className="sechead">
                  <div className="t">Gateways</div>
                  <div className="r">by site</div>
                </div>
                {/* Same absent-vs-empty rule as Incidents above: gateways ===
                    null means the endpoint could not be read (unreachable
                    plane, or one old enough to predate invariant 65), never
                    shown as "nothing has pushed", which would read as
                    measured when nothing was. */}
                {gateways === null ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    Not available on this plane.
                  </div>
                ) : gateways.length === 0 ? (
                  <div className="empty" style={{ padding: "28px 20px" }}>
                    No gateways have pushed yet.
                  </div>
                ) : (
                  <div className="tablewrap">
                    <table className="narrow">
                      <thead>
                        <tr>
                          <th>Site</th>
                          <th>Spent</th>
                          <th>Last push</th>
                        </tr>
                      </thead>
                      <tbody>
                        {gateways
                          .slice()
                          .sort((a, b) => b.last_push_millis - a.last_push_millis)
                          .map((g) => {
                            const unnamed = g.site === "unnamed";
                            // A visible text label, not colour alone
                            // (invariant 65: nothing pages anybody when a
                            // site goes quiet, so this label is the only
                            // signal a human gets).
                            const silent = Date.now() - g.last_push_millis > SILENT_AFTER_MS;
                            return (
                              <tr key={g.site}>
                                <td>
                                  <span
                                    className="rid"
                                    style={unnamed ? { color: "var(--dim)" } : undefined}
                                  >
                                    {g.site}
                                  </span>
                                </td>
                                {/* Two-plus-one columns, the Owners card's own
                                    narrow-rail shape: the count rides under
                                    the spend rather than its own column. */}
                                <td className="spentcell">
                                  <div className="nrow">
                                    <b>{usd(g.spent_microusd)}</b>
                                  </div>
                                  <div className="nocap">
                                    {g.calls} {g.calls === 1 ? "call" : "calls"}
                                  </div>
                                </td>
                                <td>
                                  <div style={silent ? { color: "var(--amber)" } : undefined}>
                                    {ago(g.last_push_millis)}
                                  </div>
                                  {silent && <div className="nocap">silent</div>}
                                </td>
                              </tr>
                            );
                          })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div className="card">
                <div className="sechead">
                  <div className="t">Spend by run</div>
                  <div className="r">run lifetime</div>
                </div>
                <div className="barchart">
                  {runs.slice(0, 6).map((r) => {
                    const budget = budgets[r.run_id] || 0;
                    const frac = budget > 0 ? r.spent_microusd / budget : 0;
                    return (
                      <div className="bc" key={r.run_id}>
                        <span className="id">{r.run_id}</span>
                        <div className={"fuse " + heatClass(frac, r.killed)}>
                          <i style={{ width: `${(r.spent_microusd / maxSpend) * 100}%` }} />
                        </div>
                        <span className="amt">{usd(r.spent_microusd)}</span>
                      </div>
                    );
                  })}
                  {runs.length === 0 && <div className="empty">—</div>}
                </div>
              </div>
            </div>
          </div>
        </>
      )}

      <footer className="foot">
        <span>
          <b>One identity</b> - the fuse, from the gateway to this dashboard
        </span>
        <span>
          <b>Live</b> · burn rate + alerts refresh every 3s
        </span>
        <span>
          <b>Kill</b> - click twice to confirm; enforced across every gateway
        </span>
      </footer>
    </div>
  );
}
