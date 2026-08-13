import { useState } from "react";
import {
  Banner,
  Checkbox,
  Empty,
  Field,
  Panel,
  PathField,
  SecretField,
  SubmitButton,
} from "../components";
import { clearSecrets, useSecret } from "../lib/secrets";
import { useOp } from "../lib/useOp";

const PFX_FILTERS = [{ name: "PKCS#12", extensions: ["pfx", "p12"] }];
const CERT_FILTERS = [{ name: "Certificate", extensions: ["crt", "cer", "pem"] }];

export function CreatePfxView() {
  const [key, setKey] = useState("");
  const [cert, setCert] = useState("");
  const [chain, setChain] = useState("");
  const [out, setOut] = useState("");
  const [legacy, setLegacy] = useState(false);
  const keyPassword = useSecret();
  const pfxPassword = useSecret();
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    try {
      await op.run({
        op: "createPfx",
        key,
        cert,
        chain: chain || null,
        out,
        keyPassword: keyPassword.value,
        pfxPassword: pfxPassword.value,
        legacy,
      });
    } finally {
      clearSecrets(keyPassword, pfxPassword);
    }
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField label="Private key" value={key} onChange={setKey} placeholder="server.key" />
          <PathField
            label="Signed certificate"
            value={cert}
            onChange={setCert}
            placeholder="server.crt"
            filters={CERT_FILTERS}
          />
          <PathField
            label="Chain (optional)"
            hint="Intermediates to embed alongside the leaf."
            value={chain}
            onChange={setChain}
            placeholder="chain.pem"
            filters={CERT_FILTERS}
          />
          <PathField
            label="Output PFX"
            value={out}
            onChange={setOut}
            placeholder="bundle.pfx"
            mode="save"
            filters={PFX_FILTERS}
          />
          <SecretField
            label="Key passphrase"
            hint="Leave empty if the private key is not encrypted."
            value={keyPassword.value}
            onChange={keyPassword.set}
          />
          <SecretField
            label="PFX export passphrase"
            value={pfxPassword.value}
            onChange={pfxPassword.set}
          />
          <Checkbox
            label="Legacy TripleDES-SHA1 encryption"
            checked={legacy}
            onChange={setLegacy}
          />
          {legacy ? (
            <span className="hint" style={{ color: "var(--warn)" }}>
              TripleDES-SHA1 is cryptographically weak. Use it only for systems that cannot read
              modern PKCS#12 — old Java keystores, Windows Server 2012, some load balancers.
            </span>
          ) : null}
          <div className="actions">
            <SubmitButton
              busy={op.busy}
              label="Build PFX"
              disabled={!key || !cert || !out || !pfxPassword.value}
            />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="PFX creation failed">{op.error}</Banner> : null}
        {op.outcome?.outcome === "pfxCreated" ? (
          <Banner tone={op.outcome.legacy ? "warn" : "ok"} title="PFX created">
            <code>{op.outcome.path}</code>
            {op.outcome.legacy ? " — legacy TripleDES-SHA1 encryption" : null}
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="No bundle yet"
            detail="A PFX packages the private key, its certificate, and any intermediates into one file."
          />
        ) : null}
      </div>
    </div>
  );
}

export function LegacyPfxView() {
  const [input, setInput] = useState("");
  const [out, setOut] = useState("");
  const inputPassword = useSecret();
  const outputPassword = useSecret();
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    try {
      await op.run({
        op: "convertPfxToLegacy",
        input,
        out,
        inputPassword: inputPassword.value,
        outputPassword: outputPassword.value,
      });
    } finally {
      clearSecrets(inputPassword, outputPassword);
    }
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="Existing PFX"
            value={input}
            onChange={setInput}
            placeholder="modern.pfx"
            filters={PFX_FILTERS}
          />
          <SecretField
            label="Existing PFX passphrase"
            value={inputPassword.value}
            onChange={inputPassword.set}
          />
          <PathField
            label="Output PFX"
            value={out}
            onChange={setOut}
            placeholder="legacy.pfx"
            mode="save"
            filters={PFX_FILTERS}
          />
          <SecretField
            label="New passphrase"
            value={outputPassword.value}
            onChange={outputPassword.set}
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Convert to legacy" disabled={!input || !out} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Conversion failed">{op.error}</Banner> : null}
        {op.outcome?.outcome === "pfxCreated" ? (
          <Banner tone="warn" title="Legacy PFX created">
            <code>{op.outcome.path}</code> — TripleDES-SHA1
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="Re-encrypt for old systems"
            detail="Rewrites an existing PFX using TripleDES-SHA1 for platforms that reject modern PKCS#12."
          />
        ) : null}
      </div>
    </div>
  );
}

export function ConvertView() {
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [format, setFormat] = useState("pem");
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "convertFormat", input, output, format });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField label="Input file" value={input} onChange={setInput} placeholder="cert.pem" />
          <Field label="Target format">
            <select value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="pem">PEM — Base64 with headers</option>
              <option value="der">DER — raw binary</option>
              <option value="base64">Base64 — body only, no headers</option>
            </select>
          </Field>
          <PathField
            label="Output file"
            value={output}
            onChange={setOutput}
            mode="save"
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Convert" disabled={!input || !output} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Conversion failed">{op.error}</Banner> : null}
        {op.outcome?.outcome === "formatConverted" ? (
          <Banner tone="ok" title={`Converted to ${op.outcome.format}`}>
            <code>{op.outcome.output}</code>
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty title="Nothing converted yet" detail="Translate between PEM, DER, and raw Base64." />
        ) : null}
      </div>
    </div>
  );
}

export function IdentifyView() {
  const [input, setInput] = useState("");
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "identifyFormat", input });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="File to identify"
            hint="Detected from content, not the file extension."
            value={input}
            onChange={setInput}
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Identify" disabled={!input} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Could not read file">{op.error}</Banner> : null}
        {op.outcome?.outcome === "formatIdentified" ? (
          <Panel title="Detected format">
            <dl className="kv">
              <dt>File</dt>
              <dd>{op.outcome.path}</dd>
              <dt>Format</dt>
              <dd>{op.outcome.description}</dd>
            </dl>
          </Panel>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="What is this file?"
            detail="Inspects the bytes to tell PEM, DER, PKCS#12, and PKCS#7 apart."
          />
        ) : null}
      </div>
    </div>
  );
}
