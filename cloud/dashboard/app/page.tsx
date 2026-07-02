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
};

type Summary = { runs: number; calls: number; spent_microusd: number };

const usd = (micro: number) => "$" + (micro / 1e6).toFixed(4);

function ago(ms: number): string {
  if (!ms) return "–";
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return Math.round(s) + "s ago";
  if (s < 3600) return Math.round(s / 60) + "m ago";
  return Math.round(s / 3600) + "h ago";
}

export default function Page() {
  const [base, setBase] = useState("");
  const [key, setKey] = useState("");
  const [connected, setConnected] = useState(false);
  const [runs, setRuns] = useState<Run[]>([]);
  const [summary, setSummary] = useState<Summary>({
    runs: 0,
    calls: 0,
    spent_microusd: 0,
  });
  const [status, setStatus] = useState("");

  useEffect(() => {
    const b = localStorage.getItem("tf_base") || "http://localhost:8080";
    const k = localStorage.getItem("tf_key") || "";
    setBase(b);
    setKey(k);
    if (k) setConnected(true);
  }, []);

  const api = useCallback(
    async (path: string, init?: RequestInit) => {
      const r = await fetch(base.replace(/\/$/, "") + path, {
        ...init,
        headers: {
          Authorization: "Bearer " + key,
          ...(init?.headers || {}),
        },
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      return r;
    },
    [base, key],
  );

  const refresh = useCallback(async () => {
    if (!connected || !key) return;
    try {
      const [runsRes, sumRes] = await Promise.all([
        api("/v1/runs"),
        api("/v1/summary"),
      ]);
      const rs: Run[] = await runsRes.json();
      rs.sort((a, b) => b.spent_microusd - a.spent_microusd);
      setRuns(rs);
      setSummary(await sumRes.json());
      setStatus("connected");
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

  const kill = async (run: string) => {
    if (!confirm(`Kill run '${run}'? Gateways will hard-stop it.`)) return;
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
    if (isNaN(n)) return alert("not a number");
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

  const maxSpend = Math.max(1, ...runs.map((r) => r.spent_microusd));

  return (
    <>
      <header className="header">
        <h1>🧯 TokenFuse Cloud</h1>
        <span className="muted">single pane of glass across your gateways</span>
        <span style={{ flex: 1 }} />
        <input
          value={base}
          onChange={(e) => setBase(e.target.value)}
          placeholder="control-plane URL"
          size={22}
        />
        <input
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="org API key"
          size={16}
        />
        <button onClick={connect}>Connect</button>
        <span className="muted">{status}</span>
      </header>

      <main>
        {!connected ? (
          <div className="empty">Enter your control-plane URL and org API key.</div>
        ) : (
          <>
            <div className="cards">
              <div className="card">
                <div className="n">{summary.runs}</div>
                <div className="l">Runs</div>
              </div>
              <div className="card">
                <div className="n">{summary.calls}</div>
                <div className="l">Calls</div>
              </div>
              <div className="card">
                <div className="n">{usd(summary.spent_microusd)}</div>
                <div className="l">Spent</div>
              </div>
            </div>

            {runs.length > 0 && (
              <div className="bars">
                <p className="section-title">Spend by run</p>
                {runs.slice(0, 8).map((r) => (
                  <div className="bar-row" key={r.run_id}>
                    <div className="bar-label">{r.run_id}</div>
                    <div className="bar-track">
                      <div
                        className="bar-fill"
                        style={{
                          width: `${(r.spent_microusd / maxSpend) * 100}%`,
                        }}
                      />
                    </div>
                    <div className="bar-val">{usd(r.spent_microusd)}</div>
                  </div>
                ))}
              </div>
            )}

            <table>
              <thead>
                <tr>
                  <th>Run</th>
                  <th>Model</th>
                  <th className="num">Spent</th>
                  <th className="num">Calls</th>
                  <th className="num">Cache hits</th>
                  <th className="num">Steps</th>
                  <th>Last seen</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => (
                  <tr key={r.run_id} style={r.killed ? { opacity: 0.55 } : undefined}>
                    <td>{r.run_id}</td>
                    <td>
                      <span className="pill">{r.model || "—"}</span>
                    </td>
                    <td className="num">{usd(r.spent_microusd)}</td>
                    <td className="num">{r.calls}</td>
                    <td className="num">{r.cache_hits}</td>
                    <td className="num">{r.steps}</td>
                    <td>{ago(r.last_seen_millis)}</td>
                    <td style={{ whiteSpace: "nowrap" }}>
                      <button
                        className="ghost"
                        style={{ marginRight: 6 }}
                        onClick={() => setBudget(r.run_id)}
                      >
                        Budget
                      </button>
                      {r.killed ? (
                        <span className="pill" style={{ color: "var(--danger)" }}>
                          killed
                        </span>
                      ) : (
                        <button className="danger" onClick={() => kill(r.run_id)}>
                          Kill
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {runs.length === 0 && (
              <div className="empty">
                No runs yet — send traffic through a gateway.
              </div>
            )}
          </>
        )}
      </main>
    </>
  );
}
