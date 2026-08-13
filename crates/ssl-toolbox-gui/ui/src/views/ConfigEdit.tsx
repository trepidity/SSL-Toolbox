import { Fragment, useState } from "react";
import { Badge, Banner, Empty, Panel, PathField, SubmitButton, sanKindInfo } from "../components";
import type { ConfigSummary } from "../lib/types";
import { runOp } from "../lib/api";

/**
 * View and edit an existing OpenSSL config.
 *
 * The text in the editor is the source of truth. The panel on the right is a
 * *reading* of that text and never writes back to it — a config carries comments,
 * extra sections and hand-tuned extensions that `ConfigInputs` cannot express, so
 * regenerating the file from a parse would quietly destroy them.
 */
export function EditConfigView() {
  const [path, setPath] = useState("");
  const [text, setText] = useState("");
  const [loadedText, setLoadedText] = useState<string | null>(null);
  const [summary, setSummary] = useState<ConfigSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const dirty = loadedText !== null && text !== loadedText;

  async function load(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const outcome = await runOp({ op: "loadConfig", path });
      if (outcome.outcome === "configLoaded") {
        setText(outcome.text);
        setLoadedText(outcome.text);
        setSummary(outcome.summary);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setSummary(null);
      setLoadedText(null);
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const outcome = await runOp({ op: "saveConfig", path, text });
      if (outcome.outcome === "configSaved") {
        setLoadedText(text);
        setSummary(outcome.summary);
        setNotice(
          outcome.backup
            ? `Saved. Previous contents kept at ${outcome.backup}`
            : "Saved.",
        );
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={load}>
          <PathField
            label="OpenSSL config"
            hint="Opened as text and saved exactly as you leave it."
            value={path}
            onChange={setPath}
            placeholder="request.cnf"
            filters={[{ name: "OpenSSL config", extensions: ["cnf", "conf", "cfg"] }]}
          />
          <div className="actions">
            <SubmitButton busy={busy} label="Load" disabled={!path} />
          </div>
        </form>

        {loadedText !== null ? (
          <Panel
            title="Config text"
            fill
            aside={dirty ? <Badge tone="warn">unsaved</Badge> : <Badge tone="ok">saved</Badge>}
          >
            <textarea
              className="code-editor"
              value={text}
              spellCheck={false}
              onChange={(event) => setText(event.target.value)}
              aria-label="OpenSSL config text"
            />
            <div className="actions">
              <button type="button" className="primary" onClick={save} disabled={busy || !dirty}>
                Save
              </button>
              <button
                type="button"
                className="ghost"
                onClick={() => setText(loadedText)}
                disabled={!dirty}
              >
                Revert
              </button>
            </div>
            <span className="hint">
              Saving keeps the previous contents as <code>{path}.bak</code>.
            </span>
          </Panel>
        ) : null}
      </div>

      <div className="pane">
        {error ? (
          <Banner tone="danger" title="Config error">
            {error}
          </Banner>
        ) : null}
        {notice ? (
          <Banner tone="ok" title="Written">
            {notice}
          </Banner>
        ) : null}
        {summary ? <ConfigSummaryPanel summary={summary} /> : null}
        {!error && !summary ? (
          <Empty
            title="No config loaded"
            detail="Point at a .cnf to read its subject, SANs, and key size — and to edit it in place."
          />
        ) : null}
      </div>
    </div>
  );
}

function ConfigSummaryPanel({ summary }: { summary: ConfigSummary }) {
  const rows: [string, string | null][] = [
    ["Common name", summary.commonName],
    ["Organization", summary.organization],
    ["Org unit", summary.orgUnit],
    ["Country", summary.country],
    ["State", summary.state],
    ["Locality", summary.locality],
    ["Email", summary.email],
    ["Key size", summary.keySize ? `${summary.keySize} bits` : null],
    ["Extended key usage", summary.extendedKeyUsage],
  ];

  return (
    <>
      <Panel title="Understood by this tool">
        <dl className="kv">
          {rows.map(([label, value]) => (
            <Fragment key={label}>
              <dt>{label}</dt>
              <dd className={value ? undefined : "muted"}>{value ?? "—"}</dd>
            </Fragment>
          ))}
        </dl>
      </Panel>

      <Panel
        title="Subject alternative names"
        aside={
          <Badge tone={summary.sans.length > 0 ? "neutral" : "warn"}>{summary.sans.length}</Badge>
        }
      >
        {summary.sans.length === 0 ? (
          <span className="muted small">This config declares no SANs.</span>
        ) : (
          <div className="pill-grid">
            {summary.sans.map((san, index) => (
              <span key={`${san.kind}-${san.value}-${index}`} className="pill">
                {sanKindInfo(san.kind).configKey} {san.value}
              </span>
            ))}
          </div>
        )}
      </Panel>

      {summary.warnings.length > 0 ? (
        <Panel
          title="Worth a look"
          aside={<Badge tone="warn">{summary.warnings.length}</Badge>}
        >
          <ul className="list">
            {summary.warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </Panel>
      ) : null}

      <Panel title="Sections" aside={<Badge tone="neutral">{summary.sections.length}</Badge>}>
        <div className="pill-grid">
          {summary.sections.map((section) => (
            <span key={section} className="pill">
              [{section}]
            </span>
          ))}
        </div>
      </Panel>
    </>
  );
}
