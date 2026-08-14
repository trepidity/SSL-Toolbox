import { useState } from "react";
import {
  Badge,
  Banner,
  CopyButton,
  Empty,
  ExpiryBadge,
  Field,
  Panel,
  SubmitButton,
} from "../components";
import { runOp } from "../lib/api";
import type { CertificateDetails, CertificateSummary } from "../lib/types";

/**
 * Find a certificate the CA has already issued.
 *
 * The gap this fills: a request ID is the only handle the rest of the app has on
 * a certificate, and nobody remembers one. Searching by hostname answers the
 * question an operator actually arrives with — "what do we have for this name,
 * and is it still good?" — and the ID it returns is the same one the Collect
 * screen takes, so finding a certificate and downloading it is one path rather
 * than two.
 *
 * The CA's list endpoint returns identifiers only, so status and the two dates
 * are filled in per row by the plugin — one extra request each, run in bounded
 * batches against a cached token. That cost buys the columns that make a results
 * list answerable at a glance; opening a row still fetches the rest (profile,
 * term, requester, comments).
 */
export function CaSearchView() {
  const [commonName, setCommonName] = useState("");
  const [san, setSan] = useState("");
  const [serial, setSerial] = useState("");
  const [status, setStatus] = useState("");
  const [size] = useState(25);

  const [results, setResults] = useState<CertificateSummary[] | null>(null);
  const [provider, setProvider] = useState("");
  const [position, setPosition] = useState(0);
  const [mayHaveMore, setMayHaveMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [openId, setOpenId] = useState<string | null>(null);
  const [details, setDetails] = useState<CertificateDetails | null>(null);
  const [detailsBusy, setDetailsBusy] = useState(false);
  const [detailsError, setDetailsError] = useState<string | null>(null);

  async function search(offset: number) {
    setBusy(true);
    setError(null);
    setOpenId(null);
    setDetails(null);
    try {
      const outcome = await runOp({
        op: "caSearchCertificates",
        commonName: commonName || null,
        subjectAlternativeName: san || null,
        serialNumber: serial || null,
        status: status || null,
        size,
        position: offset,
      });
      if (outcome.outcome === "caCertificatesFound") {
        setResults(outcome.certificates);
        setProvider(outcome.provider);
        setPosition(outcome.position);
        setMayHaveMore(outcome.mayHaveMore);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setResults(null);
    } finally {
      setBusy(false);
    }
  }

  async function openDetails(id: string) {
    if (openId === id) {
      setOpenId(null);
      setDetails(null);
      return;
    }
    setOpenId(id);
    setDetails(null);
    setDetailsError(null);
    setDetailsBusy(true);
    try {
      const outcome = await runOp({ op: "caCertificateDetails", certificateId: id });
      if (outcome.outcome === "caCertificateLoaded") setDetails(outcome.certificate);
    } catch (caught) {
      setDetailsError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setDetailsBusy(false);
    }
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            void search(0);
          }}
        >
          <div className="small muted">
            Leave every field empty to list what this account can see.
          </div>
          <Field label="Common name" hint="The certificate's primary hostname.">
            <input
              type="text"
              value={commonName}
              spellCheck={false}
              placeholder="svc.example.com"
              onChange={(event) => setCommonName(event.target.value)}
            />
          </Field>
          <Field label="Subject alternative name" hint="Matches a name in the SAN list.">
            <input
              type="text"
              value={san}
              spellCheck={false}
              onChange={(event) => setSan(event.target.value)}
            />
          </Field>
          <Field label="Serial number">
            <input
              type="text"
              value={serial}
              spellCheck={false}
              onChange={(event) => setSerial(event.target.value)}
            />
          </Field>
          <Field label="Status" hint="Blank matches every status.">
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="">Any status</option>
              <option value="Issued">Issued</option>
              <option value="Requested">Requested</option>
              <option value="Revoked">Revoked</option>
              <option value="Expired">Expired</option>
              <option value="Rejected">Rejected</option>
            </select>
          </Field>
          <div className="actions">
            <SubmitButton busy={busy} label="Search" />
          </div>
        </form>
      </div>

      <div className="pane">
        {error ? (
          <Banner tone="danger" title="Search failed">
            {error}
          </Banner>
        ) : null}

        {results ? (
          <Panel
            title={`Certificates at ${provider}`}
            aside={<Badge tone="neutral">{results.length}</Badge>}
          >
            {results.length === 0 ? (
              <span className="muted small">Nothing matched those filters.</span>
            ) : (
              <div className="rows" style={{ margin: "-13px" }}>
                {results.map((certificate) => (
                  <div key={certificate.id}>
                    <button
                      type="button"
                      className="row row-button"
                      aria-expanded={openId === certificate.id}
                      onClick={() => openDetails(certificate.id)}
                    >
                      <Badge tone="neutral">{certificate.id}</Badge>
                      <div className="grow">
                        <div className="summary">{certificate.common_name}</div>
                        <div className="muted small summary">
                          {[
                            certificate.status,
                            certificate.requested ? `req ${certificate.requested}` : null,
                            certificate.expires ? `exp ${certificate.expires}` : null,
                          ]
                            .filter(Boolean)
                            .join("  ·  ")}
                        </div>
                        {certificate.subject_alternative_names.length > 0 ? (
                          <div className="muted small summary">
                            {certificate.subject_alternative_names.join(", ")}
                          </div>
                        ) : null}
                      </div>
                      {/* An expiry date only means something relative to today;
                          the badge does that arithmetic so a stale certificate
                          is visible without reading every row's date. */}
                      {certificate.expires ? <ExpiryBadge notAfter={certificate.expires} /> : null}
                      <span className="when">{openId === certificate.id ? "▾" : "▸"}</span>
                    </button>

                    {openId === certificate.id ? (
                      <div className="row-detail">
                        {detailsBusy ? <span className="muted small">Loading…</span> : null}
                        {detailsError ? (
                          <Banner tone="danger" title="Could not read the certificate">
                            {detailsError}
                          </Banner>
                        ) : null}
                        {details ? <DetailRows details={details} /> : null}
                      </div>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </Panel>
        ) : null}

        {results && mayHaveMore ? (
          <div className="actions">
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => search(position + results.length)}
            >
              Next page
            </button>
            {position > 0 ? (
              <button
                type="button"
                className="ghost"
                disabled={busy}
                onClick={() => search(Math.max(0, position - size))}
              >
                Previous page
              </button>
            ) : null}
          </div>
        ) : null}

        {!error && !results ? (
          <Empty
            title="No search run"
            detail="Finds certificates the CA has already issued. The ID a result carries is the one the Collect screen takes."
          />
        ) : null}
      </div>
    </div>
  );
}

function DetailRows({ details }: { details: CertificateDetails }) {
  const rows: [string, string | null][] = [
    ["Status", details.status],
    ["Profile", details.profile],
    ["Serial", details.serial_number || null],
    ["Requested", details.requested],
    ["Expires", details.expires],
    ["Term", details.term_days === null ? null : `${details.term_days} days`],
    ["Requester", details.requester],
    ["Key", details.key_algorithm],
    ["Comments", details.comments],
  ];

  return (
    <>
      <dl className="kv">
        {rows
          .filter(([, value]) => value !== null && value !== "")
          .map(([label, value]) => (
            <div key={label} style={{ display: "contents" }}>
              <dt>{label}</dt>
              <dd>{value}</dd>
            </div>
          ))}
        {details.subject_alternative_names.length > 0 ? (
          <>
            <dt>SANs</dt>
            <dd>
              <ul className="list">
                {details.subject_alternative_names.map((san) => (
                  <li key={san}>{san}</li>
                ))}
              </ul>
            </dd>
          </>
        ) : null}
      </dl>
      <div className="actions">
        {/* The ID is the handle every other CA screen needs, and it is long
            enough that retyping it is a real source of error. */}
        <CopyButton text={details.id} label="Copy ID for Collect" />
      </div>
    </>
  );
}
