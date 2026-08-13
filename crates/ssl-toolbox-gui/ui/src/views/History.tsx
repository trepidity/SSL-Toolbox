import { useEffect, useState } from "react";
import { Badge, Empty, Panel } from "../components";
import { validationHistory } from "../lib/api";
import type { JobRecord, ValidationAuditEntry } from "../lib/types";

function when(timestampSecs: number): string {
  if (!timestampSecs) return "—";
  return new Date(timestampSecs * 1000).toLocaleString();
}

export function HistoryView({ recentJobs }: { recentJobs: JobRecord[] }) {
  const [audits, setAudits] = useState<ValidationAuditEntry[]>([]);

  useEffect(() => {
    validationHistory()
      .then((entries) => setAudits([...entries].reverse()))
      .catch(() => setAudits([]));
  }, []);

  return (
    <div className="main-body single">
      <div className="pane">
        <Panel title="Recent jobs" aside={<Badge tone="neutral">{recentJobs.length}</Badge>}>
          {recentJobs.length === 0 ? (
            <span className="muted small">Nothing yet — completed operations are recorded here.</span>
          ) : (
            <div className="rows" style={{ margin: "-13px" }}>
              {recentJobs.map((job, index) => (
                <div className="row" key={`${job.timestamp_secs}-${index}`}>
                  <Badge tone="neutral">{job.kind}</Badge>
                  <div className="grow">
                    <div className="summary">{job.summary}</div>
                    {Object.entries(job.outputs).length > 0 ? (
                      <div className="muted small mono summary">
                        {Object.values(job.outputs).join("  ·  ")}
                      </div>
                    ) : null}
                  </div>
                  <span className="when">{when(job.timestamp_secs)}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Endpoint validation log" aside={<Badge tone="neutral">{audits.length}</Badge>}>
          {audits.length === 0 ? (
            <span className="muted small">
              No endpoint checks recorded yet. Each verification is appended to
              <code className="mono"> ~/.ssl-toolbox/validation-log.jsonl</code>.
            </span>
          ) : (
            <div className="rows" style={{ margin: "-13px" }}>
              {audits.map((entry, index) => (
                <div className="row" key={`${entry.timestamp_secs}-${index}`}>
                  <Badge tone={entry.status === "Success" ? "ok" : "danger"}>
                    {entry.status === "Success" ? "OK" : "Fail"}
                  </Badge>
                  <div className="grow">
                    <div className="summary mono">
                      {entry.host}:{entry.port}
                    </div>
                    {entry.error ? (
                      <div className="muted small summary">{entry.error}</div>
                    ) : entry.comparison.changes.length > 0 ? (
                      <div className="muted small summary">
                        {entry.comparison.changes.join(" · ")}
                      </div>
                    ) : (
                      <div className="muted small">No change since the previous check.</div>
                    )}
                  </div>
                  <span className="when">{entry.timestamp_utc}</span>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {recentJobs.length === 0 && audits.length === 0 ? (
          <Empty
            title="No history yet"
            detail="Jobs and endpoint checks are recorded under ~/.ssl-toolbox and shared with the CLI."
          />
        ) : null}
      </div>
    </div>
  );
}
