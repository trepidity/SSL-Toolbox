import { open, save } from "@tauri-apps/plugin-dialog";
import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import type { CertDetails, CertValidation, SanKind } from "./lib/types";
import { SAN_KINDS } from "./lib/types";

/** Label / placeholder for a SAN type; falls back to DNS for an unknown value. */
export function sanKindInfo(kind: SanKind) {
  return SAN_KINDS.find((option) => option.kind === kind) ?? SAN_KINDS[0];
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

/**
 * A path input paired with a native file dialog.
 *
 * Typing a path stays possible on purpose — users paste paths from tickets and
 * terminals constantly, and a browse-only control would be slower than the CLI
 * it replaces.
 */
export function PathField({
  label,
  hint,
  value,
  onChange,
  placeholder,
  mode = "open",
  directory = false,
  filters,
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
  mode?: "open" | "save";
  directory?: boolean;
  filters?: { name: string; extensions: string[] }[];
}) {
  const [browseError, setBrowseError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Paths in this tool routinely share a long directory prefix — the key, the
  // CSR and the config all land in one folder — so the head of the string is the
  // part that carries no information and the filename is what distinguishes the
  // field. Keep the tail in view whenever the user is not actively editing.
  useEffect(() => {
    const el = inputRef.current;
    if (el && !editing) el.scrollLeft = el.scrollWidth;
  }, [value, editing]);

  async function browse() {
    // A rejected dialog must never be silent. Without this catch the rejection
    // surfaces only as an unhandled promise in devtools and the button reads as
    // dead — which is exactly how a missing ACL capability once presented.
    try {
      setBrowseError(null);
      const picked =
        mode === "save"
          ? await save({ defaultPath: value || undefined, filters })
          : await open({ multiple: false, directory, defaultPath: value || undefined, filters });
      if (typeof picked === "string") onChange(picked);
    } catch (cause) {
      setBrowseError(cause instanceof Error ? cause.message : String(cause));
    }
  }

  return (
    <Field label={label} hint={hint}>
      <div className="path-row">
        <input
          ref={inputRef}
          type="text"
          value={value}
          placeholder={placeholder}
          spellCheck={false}
          title={value || undefined}
          onChange={(event) => onChange(event.target.value)}
          onFocus={() => setEditing(true)}
          onBlur={() => setEditing(false)}
        />
        <button type="button" className="ghost" onClick={browse}>
          Browse
        </button>
      </div>
      {browseError ? <span className="hint path-error">{browseError}</span> : null}
    </Field>
  );
}

export function SecretField({
  label,
  hint,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  hint?: string;
  value: string;
  onChange: (next: string) => void;
  placeholder?: string;
}) {
  return (
    <Field label={label} hint={hint}>
      <input
        type="password"
        value={value}
        placeholder={placeholder}
        autoComplete="new-password"
        spellCheck={false}
        onChange={(event) => onChange(event.target.value)}
      />
    </Field>
  );
}

export function Checkbox({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (next: boolean) => void;
}) {
  return (
    <label className="check">
      <input type="checkbox" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

export function Panel({
  title,
  aside,
  children,
  /** Grow into the pane's spare height. For panels whose content is the work. */
  fill = false,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  fill?: boolean;
}) {
  return (
    <section className={fill ? "panel fill" : "panel"}>
      <header className="panel-head">
        <h3>{title}</h3>
        {aside}
      </header>
      <div className="panel-body">{children}</div>
    </section>
  );
}

export interface SanEntry {
  id: number;
  kind: SanKind;
  value: string;
}

export function newSanEntry(entries: SanEntry[], kind: SanKind = "dns"): SanEntry {
  return { id: entries.reduce((max, e) => Math.max(max, e.id), 0) + 1, kind, value: "" };
}

/**
 * One row per subject alternative name, each with its type stated explicitly.
 *
 * A single comma/space-separated box cannot express type at all — it forces one
 * field per SAN type and silently makes `10.0.0.5` a DNS name if it lands in the
 * wrong box. A row carries its own type, so what you see is what gets written.
 */
export function SanEditor({
  entries,
  onChange,
  hint,
}: {
  entries: SanEntry[];
  onChange: (next: SanEntry[]) => void;
  hint?: string;
}) {
  function update(id: number, patch: Partial<SanEntry>) {
    onChange(entries.map((entry) => (entry.id === id ? { ...entry, ...patch } : entry)));
  }

  return (
    <div className="field">
      <label>Subject alternative names</label>

      {entries.length === 0 ? (
        <span className="hint">None yet — the common name is always included.</span>
      ) : null}

      {entries.map((entry) => (
        <div className="san-row" key={entry.id}>
          <select
            value={entry.kind}
            aria-label="SAN type"
            onChange={(event) => update(entry.id, { kind: event.target.value as SanKind })}
          >
            {SAN_KINDS.map((option) => (
              <option key={option.kind} value={option.kind}>
                {option.label}
              </option>
            ))}
          </select>
          <input
            type="text"
            value={entry.value}
            spellCheck={false}
            aria-label={`${sanKindInfo(entry.kind).label} SAN value`}
            placeholder={sanKindInfo(entry.kind).placeholder}
            onChange={(event) => update(entry.id, { value: event.target.value })}
          />
          <button
            type="button"
            className="ghost"
            aria-label="Remove this SAN"
            title="Remove"
            onClick={() => onChange(entries.filter((candidate) => candidate.id !== entry.id))}
          >
            ✕
          </button>
        </div>
      ))}

      <div>
        <button
          type="button"
          className="ghost"
          onClick={() => onChange([...entries, newSanEntry(entries)])}
        >
          + Add SAN
        </button>
      </div>

      {hint ? <span className="hint">{hint}</span> : null}
    </div>
  );
}

export function Badge({
  tone,
  children,
}: {
  tone: "ok" | "warn" | "danger" | "neutral";
  children: ReactNode;
}) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Banner({
  tone,
  title,
  children,
}: {
  tone: "ok" | "warn" | "danger";
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className={`banner ${tone}`}>
      <div>
        <div className="banner-title">{title}</div>
        {children ? <div>{children}</div> : null}
      </div>
    </div>
  );
}

export function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

export function SubmitButton({
  busy,
  label,
  disabled,
}: {
  busy: boolean;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button type="submit" className="primary" disabled={busy || disabled}>
      {busy ? <span className="spinner" /> : null} {busy ? "Working…" : label}
    </button>
  );
}

/** Days until `notAfter`, or null when the date cannot be parsed. */
export function daysUntil(notAfter: string): number | null {
  const expiry = Date.parse(notAfter);
  if (Number.isNaN(expiry)) return null;
  return Math.floor((expiry - Date.now()) / 86_400_000);
}

export function ExpiryBadge({ notAfter }: { notAfter: string }) {
  const days = daysUntil(notAfter);
  if (days === null) return <Badge tone="neutral">Unknown expiry</Badge>;
  if (days < 0) return <Badge tone="danger">Expired</Badge>;
  if (days <= 30) return <Badge tone="warn">{days}d left</Badge>;
  return <Badge tone="ok">{days}d left</Badge>;
}

export function CertCard({
  cert,
  role,
  emphasis = false,
}: {
  cert: CertDetails;
  role?: string;
  emphasis?: boolean;
}) {
  return (
    <div className={emphasis ? "chain-node is-leaf" : "chain-node"}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 10 }}>
        {role ? <span className="chain-role">{role}</span> : <span />}
        <ExpiryBadge notAfter={cert.not_after} />
      </div>
      <div className="chain-cn">{cert.common_name}</div>
      <dl className="kv" style={{ marginTop: 8, marginBottom: 0 }}>
        <dt>Issuer</dt>
        <dd>{cert.issuer}</dd>
        <dt>Valid</dt>
        <dd>
          {cert.not_before} → {cert.not_after}
        </dd>
        <dt>Serial</dt>
        <dd>{cert.serial_number}</dd>
        <dt>Signature</dt>
        <dd>{cert.signature_algorithm}</dd>
        <dt>Key size</dt>
        <dd>{cert.public_key_bits} bits</dd>
        <dt>SHA-256</dt>
        <dd>{cert.sha256_fingerprint}</dd>
        {cert.sans.length > 0 ? (
          <>
            <dt>SANs</dt>
            <dd>
              <ul className="list">
                {cert.sans.map((san) => (
                  <li key={san}>{san}</li>
                ))}
              </ul>
            </dd>
          </>
        ) : null}
      </dl>
    </div>
  );
}

/** Leaf → intermediates → root, rendered in the reconstructed path order. */
/**
 * `leafLabel` names the end-entity certificate. It defaults to the server case
 * because that is what this toolbox is pointed at, but a chain from a client
 * certificate can override it rather than being mislabelled.
 */
export function CertChain({
  chain,
  leafLabel = "Server certificate",
}: {
  chain: CertDetails[];
  leafLabel?: string;
}) {
  return (
    <div className="chain">
      {chain.map((cert, index) => {
        const isLeaf = index === 0;
        // A certificate is only a root when it signed itself. Treating the last
        // element as the root is wrong for the common case: servers usually send
        // the intermediate and omit the root entirely.
        const selfSigned = cert.issuer === cert.common_name;
        const role =
          selfSigned && chain.length === 1
            ? "Self-signed certificate"
            : isLeaf
              ? leafLabel
              : selfSigned
                ? "Root CA"
                : "Intermediate CA";

        return (
          <div key={`${cert.sha256_fingerprint}-${index}`}>
            {index > 0 ? <div className="chain-link">└─ issued by</div> : null}
            <CertCard cert={cert} role={role} emphasis={isLeaf} />
          </div>
        );
      })}
    </div>
  );
}

export function ValidationChecks({ validation }: { validation: CertValidation }) {
  const rows = [
    { label: "Hostname", result: validation.hostname_match },
    { label: "Expiry", result: validation.expiry_check },
    { label: "Chain of trust", result: validation.chain_valid },
  ].filter((row) => row.result !== null);

  if (rows.length === 0) {
    return <span className="muted small">Certificate validation was not requested.</span>;
  }

  return (
    <div className="checks">
      {rows.map(({ label, result }) => (
        <div key={label} className={`check-row ${result!.passed ? "pass" : "fail"}`}>
          <span className="mark">{result!.passed ? "✓" : "✗"}</span>
          <div>
            <div>{label}</div>
            <div className="detail">{result!.message}</div>
          </div>
        </div>
      ))}
    </div>
  );
}
