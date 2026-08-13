import { useState } from "react";
import { Badge, Banner, Empty, Field, Panel, PathField, SubmitButton } from "../components";
import { useOp } from "../lib/useOp";

/**
 * CA operations reach the network with credentials from `.env` /
 * `.ssl-toolbox/sectigo.json`. Configuration lives outside the app on purpose —
 * this UI never asks for or stores API credentials.
 */
export function CaProfilesView() {
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "caListProfiles" });
  }

  const listed = op.outcome?.outcome === "caProfilesListed" ? op.outcome : null;

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <div className="small muted">
            Reads credentials from <code className="mono">SCM_CLIENT_ID</code> /
            <code className="mono"> SCM_CLIENT_SECRET</code> and the endpoint settings in
            <code className="mono"> .ssl-toolbox/sectigo.json</code>.
          </div>
          <div className="actions">
            <SubmitButton busy={op.busy} label="Fetch profiles" />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? (
          <Banner tone="danger" title="Could not reach the CA">
            {op.error}
          </Banner>
        ) : null}
        {listed ? (
          <Panel
            title={`Profiles from ${listed.provider}`}
            aside={<Badge tone="neutral">{listed.profiles.length}</Badge>}
          >
            {listed.profiles.length === 0 ? (
              <span className="muted small">This account has no certificate profiles.</span>
            ) : (
              <div className="rows" style={{ margin: "-13px" }}>
                {listed.profiles.map((profile) => (
                  <div className="row" key={profile.id}>
                    <Badge tone="neutral">{profile.id}</Badge>
                    <div className="grow">
                      <div className="summary">{profile.name}</div>
                      {profile.description ? (
                        <div className="muted small summary">{profile.description}</div>
                      ) : null}
                    </div>
                    {profile.terms.length > 0 ? (
                      <span className="when">{profile.terms.join(" / ")} d</span>
                    ) : null}
                  </div>
                ))}
              </div>
            )}
          </Panel>
        ) : null}
        {!op.error && !listed ? (
          <Empty
            title="No profiles fetched"
            detail="Lists the certificate types this CA account can issue, with their allowed terms."
          />
        ) : null}
      </div>
    </div>
  );
}

export function CaSubmitView() {
  const [csr, setCsr] = useState("");
  const [out, setOut] = useState("");
  const [description, setDescription] = useState("");
  const [productCode, setProductCode] = useState("");
  const [termDays, setTermDays] = useState("");
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const parsedTerm = Number(termDays);
    await op.run({
      op: "caSubmitCsr",
      csr,
      out,
      description: description || null,
      productCode: productCode || null,
      termDays: termDays && Number.isFinite(parsedTerm) ? parsedTerm : null,
    });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="CSR to submit"
            value={csr}
            onChange={(next) => {
              setCsr(next);
              if (!out) setOut(next.replace(/\.[^./\\]+$/, "") + ".request-id");
            }}
            placeholder="server.csr"
            filters={[{ name: "CSR", extensions: ["csr", "pem"] }]}
          />
          <PathField
            label="Save request ID to"
            hint="You need this ID to collect the signed certificate later."
            value={out}
            onChange={setOut}
            mode="save"
          />
          <Field label="Description" hint="Optional label shown in the CA console.">
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
          <Field label="Product code" hint="Optional — overrides the configured default profile.">
            <input
              type="text"
              value={productCode}
              onChange={(e) => setProductCode(e.target.value)}
            />
          </Field>
          <Field label="Term (days)" hint="Optional — must be a term the profile allows.">
            <input
              type="number"
              value={termDays}
              min={1}
              onChange={(e) => setTermDays(e.target.value)}
            />
          </Field>
          <div className="actions">
            <SubmitButton busy={op.busy} label="Submit CSR" disabled={!csr || !out} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? (
          <Banner tone="danger" title="Submission failed">
            {op.error}
          </Banner>
        ) : null}
        {op.outcome?.outcome === "caCsrSubmitted" ? (
          <Banner tone="ok" title="CSR submitted">
            Request ID <code>{op.outcome.requestId}</code> saved to{" "}
            <code>{op.outcome.path}</code>
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="Nothing submitted"
            detail="Sends a CSR to the configured CA for signing and records the request ID it returns."
          />
        ) : null}
      </div>
    </div>
  );
}

export function CaCollectView() {
  const [requestId, setRequestId] = useState("");
  const [out, setOut] = useState("");
  const [format, setFormat] = useState("pem");
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "caCollectCert", requestId, out, format });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <Field label="Request ID" hint="Returned when the CSR was submitted.">
            <input
              type="text"
              value={requestId}
              spellCheck={false}
              onChange={(e) => setRequestId(e.target.value)}
            />
          </Field>
          <Field label="Format">
            <select value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="pem">PEM — leaf certificate only</option>
              <option value="chain">Chain — leaf plus intermediates</option>
              <option value="pkcs7">PKCS#7</option>
            </select>
          </Field>
          <PathField label="Save certificate to" value={out} onChange={setOut} mode="save" />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Collect certificate" disabled={!requestId || !out} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? (
          <Banner tone="danger" title="Collection failed">
            {op.error}
          </Banner>
        ) : null}
        {op.outcome?.outcome === "caCertCollected" ? (
          <Banner tone="ok" title="Certificate collected">
            <code>{op.outcome.path}</code> ({op.outcome.format})
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="Nothing collected"
            detail="Downloads a signed certificate once the CA has issued it. Chain format is usually what a server wants."
          />
        ) : null}
      </div>
    </div>
  );
}
