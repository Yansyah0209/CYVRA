"use client";
import { useEffect, useState } from "react";
import {
  ArrowUpRight,
  Download,
  Globe,
  History,
  Check,
  Minus,
  AlertTriangle,
} from "lucide-react";
type Finding = {
  id: string;
  title: string;
  severity: string;
  classification: string;
  location: string;
  evidence: string;
  impact: string;
  recommendation: string;
  verification: string;
  reference: string;
};
type Report = {
  id: string;
  url: string;
  created_at: string;
  http_status: number;
  scope: string;
  summary: Record<string, number>;
  findings: Finding[];
  checks: { id: string; name: string; status: string }[];
  cookies: {
    name: string;
    secure: boolean;
    http_only: boolean;
    same_site: string;
  }[];
  redirects: { from: string; to: string; status: number }[];
  notes: string[];
  coverage: { body_inspected: boolean; body_truncated: boolean };
  limitations: string[];
};
type Saved = Pick<Report, "id" | "url" | "created_at" | "summary">;
async function request<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch("/api/web/assessments" + path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail),
    );
  return data;
}
export default function WebsiteCheck() {
  const [url, setUrl] = useState(""),
    [authorized, setAuthorized] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [report, setReport] = useState<Report | null>(null),
    [saved, setSaved] = useState<Saved[]>([]),
    [detail, setDetail] = useState<string | null>(null),
    [filter, setFilter] = useState("all");
  useEffect(() => {
    request<Saved[]>("")
      .then(setSaved)
      .catch((e) => setError(e.message));
  }, []);
  async function run(work: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await work();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Assessment failed");
    } finally {
      setBusy(false);
    }
  }
  async function assess() {
    await run(async () => {
      const r = await request<Report>("", { url: url.trim(), authorized });
      setReport(r);
      setDetail(null);
      setFilter("all");
      setSaved(await request<Saved[]>(""));
    });
  }
  async function open(id: string) {
    await run(async () => {
      setReport(await request<Report>("/" + id));
      setDetail(null);
      setFilter("all");
    });
  }
  function exportReport() {
    if (!report) return;
    const link = document.createElement("a");
    const object = URL.createObjectURL(
      new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
    );
    link.href = object;
    link.download = "cyvra-web-" + report.id + ".json";
    link.click();
    URL.revokeObjectURL(object);
  }
  const findings =
    report?.findings.filter((f) => filter === "all" || f.severity === filter) ||
    [];
  return (
    <div className="web-workspace">
      <section className="card web-entry">
        <div className="web-entry-heading">
          <div className="web-entry-icon">
            <Globe size={22} />
          </div>
          <div>
            <h2>Check a website</h2>
            <p className="muted">
              Inspect a public page. Review evidence. Fix what matters.
            </p>
          </div>
        </div>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            assess();
          }}
        >
          <div className="url-row">
            <input
              autoComplete="url"
              type="url"
              aria-label="Website URL"
              placeholder="https://your-website.com"
              value={url}
              maxLength={2000}
              onChange={(e) => setUrl(e.target.value)}
              disabled={busy}
              required
            />
            <button className="primary" disabled={busy || !authorized || !url}>
              {busy ? "Checking…" : "Check website"}
              <ArrowUpRight size={16} />
            </button>
          </div>
          <label className="authorization">
            <input
              type="checkbox"
              checked={authorized}
              onChange={(e) => setAuthorized(e.target.checked)}
              disabled={busy}
            />
            I own this website or have permission to assess it.
          </label>
        </form>
        <div className="check-scope">
          <span>HTTPS & headers</span>
          <span>Cookie attributes</span>
          <span>Static exposure markers</span>
          <span>One public page</span>
        </div>
        <p className="scope-note">
          No login or exploit attempts. Query parameters are removed. This check
          cannot establish that a website is leak-free.
        </p>
      </section>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      {busy && (
        <p className="loading" role="status">
          Fetching the page and evaluating observable configuration…
        </p>
      )}
      {report ? (
        <>
          <div className="report-heading">
            <div>
              <span className="eyebrow">WEBSITE ASSESSMENT</span>
              <h2>{report.url}</h2>
              <p className="muted">
                HTTP {report.http_status} ·{" "}
                {new Date(report.created_at).toLocaleString()} · Saved report
              </p>
            </div>
            <button onClick={exportReport}>
              <Download size={15} />
              Export report
            </button>
          </div>
          <div className="stats web-stats">
            {[
              { s: "high", label: "HIGH PRIORITY" },
              { s: "medium", label: "MEDIUM PRIORITY" },
              { s: "low", label: "CONFIGURATION REVIEWS" },
              { s: "info", label: "INFORMATIONAL" },
            ].map(({ s, label }) => (
              <section className="card" key={s}>
                <div className="card-label">{label}</div>
                <div className={"stat-number " + (report.summary[s] ? s : "")}>
                  {report.summary[s]}
                </div>
                <p>
                  {s === "high"
                    ? "Potential exposure · verify context"
                    : s === "info"
                      ? "Observations for review"
                      : "Review the evidence and applicability"}
                </p>
              </section>
            ))}
          </div>
          {report.notes.map((n, i) => (
            <div className="notice" key={i}>
              {n}
            </div>
          ))}
          {report.coverage.body_truncated && (
            <div className="notice">
              Body inspection stopped at 512 KiB. Content beyond this limit was
              not assessed.
            </div>
          )}
          <div className="web-results-grid">
            <section className="card web-findings">
              <div className="section-title">
                <h3>
                  Findings{" "}
                  <span className="count">{report.findings.length}</span>
                </h3>
                <select
                  aria-label="Filter web findings"
                  value={filter}
                  onChange={(e) => setFilter(e.target.value)}
                >
                  <option value="all">All priorities</option>
                  {["high", "medium", "low", "info"].map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </div>
              {findings.map((f) => (
                <article className="web-finding" key={f.id}>
                  <button
                    className="finding-toggle"
                    aria-expanded={detail === f.id}
                    onClick={() => setDetail(detail === f.id ? null : f.id)}
                  >
                    <div>
                      <span className={"badge " + f.severity}>
                        {f.severity}
                      </span>
                      <strong>{f.title}</strong>
                      <small>{f.classification.replaceAll("_", " ")}</small>
                    </div>
                    <span>{detail === f.id ? "−" : "+"}</span>
                  </button>
                  {detail === f.id && (
                    <div className="finding-details">
                      <dl>
                        <dt>Location</dt>
                        <dd>{f.location}</dd>
                        <dt>Observed evidence</dt>
                        <dd>{f.evidence}</dd>
                        <dt>Potential impact</dt>
                        <dd>{f.impact}</dd>
                        <dt>Recommended action</dt>
                        <dd>{f.recommendation}</dd>
                        <dt>Verification</dt>
                        <dd>{f.verification}</dd>
                      </dl>
                      <a href={f.reference} target="_blank" rel="noreferrer">
                        Methodology reference <ArrowUpRight size={12} />
                      </a>
                    </div>
                  )}
                </article>
              ))}
              {!findings.length && (
                <div className="no-findings">
                  <Check size={24} />
                  <h3>No findings in this view</h3>
                  <p className="muted">
                    Only the listed checks and inspected response are covered.
                    This is not a guarantee of security.
                  </p>
                </div>
              )}
            </section>
            <section className="card checks-panel">
              <h3>Checks & coverage</h3>
              {report.checks.map((c) => (
                <div className="check-row" key={c.id}>
                  <span>{c.name}</span>
                  <span className={"check-status " + c.status}>
                    {c.status === "pass" ? (
                      <Check size={14} />
                    ) : c.status === "review" ? (
                      <AlertTriangle size={14} />
                    ) : (
                      <Minus size={14} />
                    )}{" "}
                    {c.status.replaceAll("_", " ")}
                  </span>
                </div>
              ))}
              <p className="scope-note">{report.scope}</p>
              <details>
                <summary>What this report does not cover</summary>
                <ul>
                  {report.limitations.map((l) => (
                    <li key={l}>{l}</li>
                  ))}
                </ul>
              </details>
            </section>
          </div>
        </>
      ) : (
        <section className="web-intro">
          <div>
            <span className="eyebrow">A DIRECT STARTING POINT</span>
            <h3>From a URL to a reviewable report.</h3>
            <p>
              CYVRA checks what the public response actually reveals. Each
              finding includes its location, observed evidence, potential
              impact, and a practical recommendation.
            </p>
          </div>
          <div className="intro-list">
            <div>
              <span>01</span>Fetch a bounded public response
            </div>
            <div>
              <span>02</span>Evaluate configuration and exposure markers
            </div>
            <div>
              <span>03</span>Save findings for developer review
            </div>
          </div>
        </section>
      )}
      {saved.length > 0 && (
        <section className="card saved-assessments">
          <div className="section-title">
            <h3>
              <History size={16} />
              Recent assessments
            </h3>
            <span className="muted">Last 20 reports</span>
          </div>
          {saved.map((r) => (
            <button
              disabled={busy}
              key={r.id}
              className={
                "saved-report " + (r.id === report?.id ? "selected" : "")
              }
              onClick={() => open(r.id)}
            >
              <span>
                <strong>{r.url}</strong>
                <small>{new Date(r.created_at).toLocaleString()}</small>
              </span>
              <span>
                {Object.values(r.summary).reduce((a, b) => a + b, 0)} findings{" "}
                <ArrowUpRight size={14} />
              </span>
            </button>
          ))}
        </section>
      )}
    </div>
  );
}
