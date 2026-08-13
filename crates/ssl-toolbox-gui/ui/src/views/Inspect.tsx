import { useState } from "react";
import {
  Badge,
  Banner,
  CertCard,
  CertChain,
  Empty,
  Panel,
  PathField,
  SecretField,
  SubmitButton,
} from "../components";
import { clearSecrets, useSecret } from "../lib/secrets";
import { useOp } from "../lib/useOp";

export function InspectCertView() {
  const [input, setInput] = useState("");
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "inspectCert", input });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="Certificate file"
            hint="PEM bundles are expanded into the full chain."
            value={input}
            onChange={setInput}
            placeholder="server.crt"
            filters={[{ name: "Certificate", extensions: ["crt", "cer", "pem"] }]}
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Inspect" disabled={!input} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Could not read certificate">{op.error}</Banner> : null}
        {op.outcome?.outcome === "certInspected" ? (
          <Panel
            title={op.outcome.chain.length > 1 ? "Certificate chain" : "Certificate"}
            aside={<Badge tone="neutral">{op.outcome.chain.length} cert{op.outcome.chain.length === 1 ? "" : "s"}</Badge>}
          >
            <CertChain chain={op.outcome.chain} />
          </Panel>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="No certificate loaded"
            detail="Subject, issuer, validity window, SANs, and fingerprints."
          />
        ) : null}
      </div>
    </div>
  );
}

export function InspectCsrView() {
  const [input, setInput] = useState("");
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "inspectCsr", input });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="CSR file"
            value={input}
            onChange={setInput}
            placeholder="server.csr"
            filters={[{ name: "CSR", extensions: ["csr", "pem"] }]}
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Inspect" disabled={!input} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Could not read CSR">{op.error}</Banner> : null}
        {op.outcome?.outcome === "csrInspected" ? (
          <Panel title="Certificate signing request">
            <dl className="kv">
              <dt>Common Name</dt>
              <dd>{op.outcome.commonName}</dd>
              <dt>SANs</dt>
              <dd>
                {op.outcome.sans.length === 0 ? (
                  <span className="muted">None — the CA may reject this for a TLS server cert.</span>
                ) : (
                  <ul className="list">
                    {op.outcome.sans.map((san) => (
                      <li key={san}>{san}</li>
                    ))}
                  </ul>
                )}
              </dd>
            </dl>
          </Panel>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="No CSR loaded"
            detail="Check the subject and SANs before sending a request to a CA."
          />
        ) : null}
      </div>
    </div>
  );
}

export function InspectPfxView() {
  const [input, setInput] = useState("");
  const password = useSecret();
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    try {
      await op.run({ op: "inspectPfx", input, password: password.value });
    } finally {
      clearSecrets(password);
    }
  }

  const details = op.outcome?.outcome === "pfxInspected" ? op.outcome.details : null;

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="PFX / PKCS#12 file"
            value={input}
            onChange={setInput}
            placeholder="bundle.pfx"
            filters={[{ name: "PKCS#12", extensions: ["pfx", "p12"] }]}
          />
          <SecretField label="PFX passphrase" value={password.value} onChange={password.set} />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Open PFX" disabled={!input} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Could not open PFX">{op.error}</Banner> : null}
        {details ? (
          <>
            <Panel
              title="Private key"
              aside={
                details.private_key.present ? (
                  <Badge tone={details.private_key.matches_leaf_certificate ? "ok" : "danger"}>
                    {details.private_key.matches_leaf_certificate ? "Matches cert" : "Mismatch"}
                  </Badge>
                ) : (
                  <Badge tone="warn">Absent</Badge>
                )
              }
            >
              {details.private_key.present ? (
                <dl className="kv">
                  <dt>Algorithm</dt>
                  <dd>{details.private_key.algorithm}</dd>
                  <dt>Key size</dt>
                  <dd>{details.private_key.key_size_bits} bits</dd>
                  <dt>Security level</dt>
                  <dd>{details.private_key.security_bits} bits</dd>
                </dl>
              ) : (
                <span className="muted small">
                  This bundle contains no private key — it cannot be used to serve TLS.
                </span>
              )}
              {details.private_key.present && !details.private_key.matches_leaf_certificate ? (
                <div style={{ marginTop: 10 }}>
                  <Banner tone="danger" title="Key does not match the certificate">
                    This bundle will fail to load on any server.
                  </Banner>
                </div>
              ) : null}
            </Panel>
            <Panel
              title="Certificates"
              aside={<Badge tone="neutral">{details.cert_chain.length}</Badge>}
            >
              {details.cert_chain.length === 0 ? (
                <span className="muted small">No certificates in this bundle.</span>
              ) : (
                <CertChain chain={details.cert_chain} />
              )}
            </Panel>
          </>
        ) : null}
        {!op.error && !details ? (
          <Empty
            title="No bundle opened"
            detail="Shows what is actually inside a PFX — and whether the key matches the certificate."
          />
        ) : null}
      </div>
    </div>
  );
}

/** Re-exported for the single-cert case so the chain view stays the default. */
export { CertCard };
