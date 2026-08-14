import { useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  Banner,
  Checkbox,
  Empty,
  Field,
  Panel,
  PathField,
  SanEditor,
  SecretField,
  SubmitButton,
} from "../components";
import type { SanEntry } from "../components";
import { clearSecrets, useSecret } from "../lib/secrets";
import { useOp } from "../lib/useOp";
import type { CsrDefaults } from "../lib/types";

const KEY_FILTERS = [{ name: "Private key", extensions: ["key", "pem"] }];
const CONF_FILTERS = [{ name: "OpenSSL config", extensions: ["cnf", "conf"] }];
const CSR_FILTERS = [{ name: "CSR", extensions: ["csr", "pem"] }];

/** Swap a path's extension, so naming a config auto-names the key and CSR. */
function withExtension(path: string, extension: string): string {
  if (!path) return "";
  const trimmed = path.replace(/\.[^./\\]+$/, "");
  return `${trimmed}.${extension}`;
}

export function CreateKeyView() {
  const [out, setOut] = useState("");
  const password = useSecret();
  const confirm = useSecret();
  const op = useOp();

  const mismatch = confirm.value.length > 0 && password.value !== confirm.value;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (mismatch) return;
    try {
      await op.run({ op: "createKey", out, password: password.value });
    } finally {
      clearSecrets(password, confirm);
    }
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="Output key file"
            hint="An encrypted RSA-2048 private key is written here."
            value={out}
            onChange={setOut}
            placeholder="server.key"
            mode="save"
            filters={KEY_FILTERS}
          />
          <SecretField
            label="Passphrase"
            hint="Required — the toolbox only writes encrypted keys."
            value={password.value}
            onChange={password.set}
          />
          <SecretField
            label="Confirm passphrase"
            value={confirm.value}
            onChange={confirm.set}
          />
          {mismatch ? <span className="hint" style={{ color: "var(--danger)" }}>Passphrases do not match.</span> : null}
          <div className="actions">
            <SubmitButton
              busy={op.busy}
              label="Create key"
              disabled={!out || !password.value || mismatch}
            />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Key creation failed">{op.error}</Banner> : null}
        {op.outcome?.outcome === "keyCreated" ? (
          <Banner tone="ok" title="Private key created">
            <code>{op.outcome.path}</code>
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="No key yet"
            detail="Choose an output path and a passphrase. The key never leaves this machine."
          />
        ) : null}
      </div>
    </div>
  );
}

export function GenerateCsrView() {
  const [conf, setConf] = useState("");
  const [key, setKey] = useState("");
  const [csr, setCsr] = useState("");
  const [createKey, setCreateKey] = useState(true);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const keyPassword = useSecret();
  const op = useOp();
  const csrOutcome = op.outcome?.outcome === "csrGenerated" ? op.outcome : null;

  function onConfChange(next: string) {
    setConf(next);
    if (!key) setKey(withExtension(next, "key"));
    if (!csr) setCsr(withExtension(next, "csr"));
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setCopyState("idle");
    try {
      await op.run({
        op: "generateCsr",
        conf,
        key,
        csr,
        keyPassword: keyPassword.value,
        createKeyIfMissing: createKey,
      });
    } finally {
      clearSecrets(keyPassword);
    }
  }

  async function copyCsr(csrPem: string) {
    try {
      await writeText(csrPem);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="OpenSSL config"
            hint="Subject fields come from [req_distinguished_name]; SANs from [ alt_names ]."
            value={conf}
            onChange={onConfChange}
            placeholder="request.cnf"
            filters={CONF_FILTERS}
          />
          <PathField
            label="Private key"
            value={key}
            onChange={setKey}
            placeholder="server.key"
            mode="save"
            filters={KEY_FILTERS}
          />
          <PathField
            label="Output CSR"
            value={csr}
            onChange={setCsr}
            placeholder="server.csr"
            mode="save"
            filters={CSR_FILTERS}
          />
          <SecretField
            label="Key passphrase"
            hint={
              createKey
                ? "Used to unlock an existing key, or to encrypt a newly created one."
                : "Passphrase for the existing private key."
            }
            value={keyPassword.value}
            onChange={keyPassword.set}
          />
          <Checkbox
            label="Create the private key if it does not exist"
            checked={createKey}
            onChange={setCreateKey}
          />
          <div className="actions">
            <SubmitButton
              busy={op.busy}
              label="Generate CSR"
              disabled={!conf || !key || !csr}
            />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="CSR generation failed">{op.error}</Banner> : null}
        {csrOutcome ? (
          <>
            <Banner
              tone="ok"
              title="CSR generated"
              aside={
                <button
                  type="button"
                  className="ghost"
                  onClick={() => copyCsr(csrOutcome.csrPem)}
                >
                  {copyState === "copied" ? "Copied" : "Copy CSR"}
                </button>
              }
            >
              <code>{csrOutcome.csrPath}</code>
            </Banner>
            <Panel title="Private key">
              <div className="small">
                {csrOutcome.keyCreated ? (
                  <>
                    A new encrypted key was created at <code className="mono">{csrOutcome.keyPath}</code>.
                    Back it up — the CSR is worthless without it.
                  </>
                ) : (
                  <>
                    Reused the existing key at <code className="mono">{csrOutcome.keyPath}</code>.
                  </>
                )}
              </div>
            </Panel>
            <Panel title="Certificate signing request">
              <pre className="pem-output">{csrOutcome.csrPem}</pre>
              {copyState === "failed" ? (
                <span className="hint copy-error" role="status">
                  Could not copy the CSR. Select the text and copy it manually.
                </span>
              ) : null}
            </Panel>
          </>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="No CSR yet"
            detail="Point at an OpenSSL config. The key and CSR paths are named for you from it."
          />
        ) : null}
      </div>
    </div>
  );
}

export function NewConfigView({ defaults }: { defaults: CsrDefaults }) {
  const [form, setForm] = useState({
    common_name: "",
    country: defaults.country,
    state: defaults.state,
    locality: defaults.locality,
    organization: defaults.organization,
    org_unit: defaults.org_unit,
    email: defaults.email,
    key_size: 2048,
    extended_key_usage: "serverAuth",
  });
  const [sans, setSans] = useState<SanEntry[]>([]);
  const [out, setOut] = useState("");
  const op = useOp();

  function set<K extends keyof typeof form>(field: K, value: (typeof form)[K]) {
    setForm((prev) => ({ ...prev, [field]: value }));
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({
      op: "generateConfig",
      inputs: {
        ...form,
        // Rows already carry their type; empties are dropped rather than written.
        sans: sans
          .filter((entry) => entry.value.trim() !== "")
          .map((entry) => ({ kind: entry.kind, value: entry.value.trim() })),
      },
      out: out || `${form.common_name}.cnf`,
    });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <Field label="Common Name" hint="Also emitted as DNS.1 in the SAN list.">
            <input
              type="text"
              value={form.common_name}
              placeholder="svc.example.com"
              onChange={(e) => set("common_name", e.target.value)}
            />
          </Field>
          <Field label="Organization">
            <input
              type="text"
              value={form.organization}
              onChange={(e) => set("organization", e.target.value)}
            />
          </Field>
          <div style={{ display: "grid", gap: 12, gridTemplateColumns: "1fr 1fr" }}>
            <Field label="Country">
              <input
                type="text"
                maxLength={2}
                value={form.country}
                placeholder="US"
                onChange={(e) => set("country", e.target.value.toUpperCase())}
              />
            </Field>
            <Field label="State / Province">
              <input type="text" value={form.state} onChange={(e) => set("state", e.target.value)} />
            </Field>
            <Field label="Locality">
              <input
                type="text"
                value={form.locality}
                onChange={(e) => set("locality", e.target.value)}
              />
            </Field>
            <Field label="Org Unit">
              <input
                type="text"
                value={form.org_unit}
                onChange={(e) => set("org_unit", e.target.value)}
              />
            </Field>
          </div>
          <Field label="Email">
            <input type="text" value={form.email} onChange={(e) => set("email", e.target.value)} />
          </Field>
          <SanEditor
            entries={sans}
            onChange={setSans}
            hint="The common name is written as DNS.1 automatically — list only the additional names here."
          />
          <div style={{ display: "grid", gap: 12, gridTemplateColumns: "1fr 1fr" }}>
            <Field label="Key size">
              <select
                value={form.key_size}
                onChange={(e) => set("key_size", Number(e.target.value))}
              >
                <option value={2048}>2048 — widely compatible</option>
                <option value={4096}>4096 — stronger, slower</option>
              </select>
            </Field>
            <Field label="Extended Key Usage">
              <select
                value={form.extended_key_usage}
                onChange={(e) => set("extended_key_usage", e.target.value)}
              >
                <option value="serverAuth">Server Auth</option>
                <option value="clientAuth">Client Auth</option>
                <option value="serverAuth, clientAuth">Both (mTLS)</option>
              </select>
            </Field>
          </div>
          <PathField
            label="Output .cnf"
            hint={form.common_name ? `Defaults to ${form.common_name}.cnf` : undefined}
            value={out}
            onChange={setOut}
            mode="save"
            filters={CONF_FILTERS}
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Write config" disabled={!form.common_name} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Could not write config">{op.error}</Banner> : null}
        {op.outcome?.outcome === "configWritten" ? (
          <Banner tone="ok" title="Config written">
            <code>{op.outcome.path}</code>
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="No config yet"
            detail="Fill in the subject. Organization defaults come from ~/.ssl-toolbox/config.json."
          />
        ) : null}
      </div>
    </div>
  );
}

export function ConfigFromExistingView() {
  const [input, setInput] = useState("");
  const [out, setOut] = useState("");
  const [isCsr, setIsCsr] = useState(false);
  const op = useOp();

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "generateConfigFromCertOrCsr", input, out, isCsr });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="Existing certificate or CSR"
            hint="Its subject and SANs become the new config."
            value={input}
            onChange={(next) => {
              setInput(next);
              if (!out) setOut(withExtension(next, "cnf"));
              setIsCsr(/\.csr$/i.test(next));
            }}
            placeholder="server.crt"
          />
          <Checkbox label="Input is a CSR (not a certificate)" checked={isCsr} onChange={setIsCsr} />
          <PathField
            label="Output .cnf"
            value={out}
            onChange={setOut}
            mode="save"
            filters={CONF_FILTERS}
          />
          <div className="actions">
            <SubmitButton busy={op.busy} label="Generate config" disabled={!input || !out} />
          </div>
        </form>
      </div>
      <div className="pane">
        {op.error ? <Banner tone="danger" title="Could not generate config">{op.error}</Banner> : null}
        {op.outcome?.outcome === "configWritten" ? (
          <Banner tone="ok" title="Config written">
            <code>{op.outcome.path}</code>
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="Renew an existing certificate"
            detail="Turn a cert you already have into a config you can reissue from."
          />
        ) : null}
      </div>
    </div>
  );
}
