import { useState } from "react";
import {
  Badge,
  Banner,
  CertChain,
  Checkbox,
  Empty,
  Field,
  Panel,
  PathField,
  SecretField,
  SubmitButton,
  ValidationChecks,
} from "../components";
import { clearSecrets, useSecret } from "../lib/secrets";
import { useOp } from "../lib/useOp";
import type { EndpointProtocol, TlsVersionProbeResult } from "../lib/types";

const DEFAULT_PORT: Record<EndpointProtocol, number> = {
  https: 443,
  ldaps: 636,
  smtp: 587,
};

const PLACEHOLDER: Record<EndpointProtocol, string> = {
  https: "example.com  ·  https://example.com:8443",
  ldaps: "ldap.example.com",
  smtp: "smtp.example.com",
};

/** Protocol versions that should read as a finding, not a capability. */
function versionTone(probe: TlsVersionProbeResult): "on" | "off" | "legacy" {
  if (!probe.supported) return "off";
  return /1\.0|1\.1|SSL/i.test(probe.label) ? "legacy" : "on";
}

export function VerifyView({ protocol }: { protocol: EndpointProtocol }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState<string>(String(DEFAULT_PORT[protocol]));
  const [verify, setVerify] = useState(true);
  const [fullScan, setFullScan] = useState(false);
  const [exportCerts, setExportCerts] = useState(false);
  const [exportDir, setExportDir] = useState("");
  const [ldapProbe, setLdapProbe] = useState(false);
  const [bindDn, setBindDn] = useState("");
  const bindPassword = useSecret();
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const parsedPort = Number(port);
    try {
      await op.run({
        op: "verifyEndpoint",
        protocol,
        host,
        port: Number.isFinite(parsedPort) && parsedPort > 0 ? parsedPort : null,
        verify,
        fullScan,
        exportCertsDir: exportCerts && exportDir ? exportDir : null,
        ldapConfigTest:
          protocol === "ldaps" && ldapProbe
            ? {
                bindDn: bindDn || null,
                bindPassword: bindPassword.value || null,
              }
            : null,
      });
    } finally {
      clearSecrets(bindPassword);
    }
  }

  const found = op.outcome?.outcome === "endpointVerified" ? op.outcome : null;

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <Field label="Host" hint="A full URL works — scheme, path, and credentials are stripped.">
            <input
              type="text"
              value={host}
              placeholder={PLACEHOLDER[protocol]}
              spellCheck={false}
              onChange={(e) => setHost(e.target.value)}
            />
          </Field>
          <Field label="Port" hint="A port embedded in the host above takes precedence.">
            <input
              type="number"
              value={port}
              min={1}
              max={65535}
              onChange={(e) => setPort(e.target.value)}
            />
          </Field>
          <Checkbox
            label="Validate certificate (hostname, expiry, chain)"
            checked={verify}
            onChange={setVerify}
          />
          {protocol !== "smtp" ? (
            <Checkbox
              label="Full scan — probe every protocol version and cipher"
              checked={fullScan}
              onChange={setFullScan}
            />
          ) : null}
          <Checkbox
            label="Export the presented chain as PEM files"
            checked={exportCerts}
            onChange={setExportCerts}
          />
          {exportCerts ? (
            <PathField
              label="Export directory"
              value={exportDir}
              onChange={setExportDir}
              directory
              placeholder="./certs"
            />
          ) : null}
          {protocol === "ldaps" ? (
            <>
              <Checkbox
                label="Also run a RootDSE base search"
                checked={ldapProbe}
                onChange={setLdapProbe}
              />
              {ldapProbe ? (
                <>
                  <Field label="Bind DN" hint="Leave empty for an anonymous bind.">
                    <input
                      type="text"
                      value={bindDn}
                      placeholder="cn=reader,dc=example,dc=com"
                      spellCheck={false}
                      onChange={(e) => setBindDn(e.target.value)}
                    />
                  </Field>
                  {bindDn ? (
                    <SecretField
                      label="Bind password"
                      value={bindPassword.value}
                      onChange={bindPassword.set}
                    />
                  ) : null}
                </>
              ) : null}
            </>
          ) : null}
          <div className="actions">
            <SubmitButton
              busy={op.busy}
              label="Verify endpoint"
              disabled={!host || (exportCerts && !exportDir)}
            />
          </div>
          {fullScan ? (
            <span className="hint">
              A full scan opens one connection per cipher suite and can take a minute.
            </span>
          ) : null}
        </form>
      </div>

      <div className="pane">
        {op.error ? (
          <Banner tone="danger" title="Could not verify endpoint">
            {op.error}
          </Banner>
        ) : null}

        {found ? (
          <>
            {found.result.validation ? (
              <Panel title="Validation">
                <ValidationChecks validation={found.result.validation} />
              </Panel>
            ) : null}

            {found.result.chain_sent_out_of_order ? (
              <Banner tone="warn" title="Server sent its chain out of order">
                The certificates below are shown in reconstructed path order. Strict clients that do
                not build paths themselves may reject this server.
              </Banner>
            ) : null}

            <Panel
              title="Connection"
              aside={<Badge tone="neutral">{found.result.cipher.protocol}</Badge>}
            >
              <dl className="kv">
                <dt>Endpoint</dt>
                <dd>
                  {found.host}:{found.port}
                </dd>
                <dt>Cipher</dt>
                <dd>{found.result.cipher.name}</dd>
                <dt>Strength</dt>
                <dd>{found.result.cipher.bits} bits</dd>
              </dl>
            </Panel>

            {found.result.version_support.length > 0 ? (
              <Panel title="Protocol support">
                <div className="pill-grid">
                  {found.result.version_support.map((probe) => (
                    <span key={probe.label} className={`pill ${versionTone(probe)}`}>
                      {probe.label} {probe.supported ? "✓" : "✗"}
                    </span>
                  ))}
                </div>
                {found.result.version_support.some((p) => versionTone(p) === "legacy") ? (
                  <div className="hint" style={{ marginTop: 9, color: "var(--warn)" }}>
                    Deprecated protocol versions are enabled on this server.
                  </div>
                ) : null}
              </Panel>
            ) : null}

            {found.result.cipher_scan.length > 0 ? (
              <Panel title="Cipher scan">
                {found.result.cipher_scan.map((scan) => (
                  <div key={scan.protocol} style={{ marginBottom: 10 }}>
                    <div className="small muted" style={{ marginBottom: 5 }}>
                      {scan.protocol} — {scan.supported_ciphers.length} of {scan.tested_cipher_count}{" "}
                      tested suites accepted
                    </div>
                    <div className="pill-grid">
                      {scan.supported_ciphers.map((cipher) => (
                        <span key={cipher.name} className="pill">
                          {cipher.name}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </Panel>
            ) : null}

            <Panel
              title="Certificate chain"
              aside={<Badge tone="neutral">{found.result.cert_chain.length}</Badge>}
            >
              <CertChain chain={found.result.cert_chain} />
            </Panel>

            {found.ldapConfig ? (
              <Panel title="LDAP RootDSE" aside={<Badge tone="ok">{found.ldapConfig.authentication}</Badge>}>
                <dl className="kv">
                  {found.ldapConfig.attributes.map((attribute) => (
                    <div key={attribute.name} style={{ display: "contents" }}>
                      <dt>{attribute.name}</dt>
                      <dd>
                        <ul className="list">
                          {attribute.values.map((value) => (
                            <li key={value}>{value}</li>
                          ))}
                        </ul>
                      </dd>
                    </div>
                  ))}
                </dl>
              </Panel>
            ) : null}

            {found.ldapConfigError ? (
              <Banner tone="warn" title="RootDSE search failed">
                The TLS results above are still valid. {found.ldapConfigError}
              </Banner>
            ) : null}

            {found.exportedCerts.length > 0 ? (
              <Panel title="Exported certificates">
                <ul className="list">
                  {found.exportedCerts.map((path) => (
                    <li key={path}>{path}</li>
                  ))}
                </ul>
              </Panel>
            ) : null}

            {found.audit.comparison.changes.length > 0 ? (
              <Panel
                title="Changes since last check"
                aside={
                  found.audit.comparison.previous_timestamp_utc ? (
                    <span className="muted small mono">
                      {found.audit.comparison.previous_timestamp_utc}
                    </span>
                  ) : null
                }
              >
                <ul className="list">
                  {found.audit.comparison.changes.map((change) => (
                    <li key={change}>{change}</li>
                  ))}
                </ul>
              </Panel>
            ) : null}
          </>
        ) : null}

        {!op.error && !found ? (
          <Empty
            title="No endpoint checked"
            detail="Connects, reports the negotiated cipher and full certificate chain, and diffs the result against the last time you checked."
          />
        ) : null}
      </div>
    </div>
  );
}
