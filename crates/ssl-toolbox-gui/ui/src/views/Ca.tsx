import { useCallback, useEffect, useState } from "react";
import { Banner, CopyButton, Empty, Field, PathField, SubmitButton } from "../components";
import { loadSession, runOp } from "../lib/api";
import type { CaRequestRecord, CertProfile } from "../lib/types";
import { COLLECT_FORMATS } from "../lib/types";
import { useOp } from "../lib/useOp";

/**
 * CA operations reach the network with the credentials resolved by
 * `ssl-toolbox-ops`: environment variables if set, otherwise the encrypted
 * vault. Both are configured on the CA Settings screen; nothing here collects a
 * credential, and a locked vault surfaces as an ordinary operation error
 * pointing the user there.
 */

/**
 * Fetch the CA's certificate profiles on demand.
 *
 * Deliberately not fetched on mount: that would put a network call — and a
 * credential prompt — behind simply opening the submit screen. The operator asks
 * for them when they are ready to choose one.
 */
function useProfiles() {
  const [profiles, setProfiles] = useState<CertProfile[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      const outcome = await runOp({ op: "caListProfiles" });
      if (outcome.outcome === "caProfilesListed") {
        setProfiles(outcome.profiles);
      }
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
      setProfiles(null);
    } finally {
      setBusy(false);
    }
  }, []);

  return { profiles, busy, error, load };
}

export function CaSubmitView() {
  const [csr, setCsr] = useState("");
  const [out, setOut] = useState("");
  const [description, setDescription] = useState("");
  const [productCode, setProductCode] = useState("");
  const [termDays, setTermDays] = useState("");
  const { profiles, busy: loadingProfiles, error: profileError, load } = useProfiles();
  const op = useOp();

  const selected = profiles?.find((profile) => profile.id === productCode) ?? null;

  // The CA rejects a term the profile does not offer, so the term list is
  // derived from the chosen profile rather than typed. Changing profile clears
  // a term the new profile may not allow.
  function chooseProfile(id: string) {
    setProductCode(id);
    const profile = profiles?.find((candidate) => candidate.id === id);
    const terms = profile?.terms ?? [];
    setTermDays(terms.length > 0 ? String(Math.max(...terms)) : "");
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    const parsedTerm = Number(termDays);
    await op.run({
      op: "caSubmitCsr",
      csr,
      out: out || null,
      description: description || null,
      productCode: productCode || null,
      termDays: termDays && Number.isFinite(parsedTerm) ? parsedTerm : null,
    });
  }

  const terms = selected?.terms ?? [];

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          <PathField
            label="CSR to submit"
            value={csr}
            onChange={setCsr}
            placeholder="server.csr"
            filters={[{ name: "CSR", extensions: ["csr", "pem"] }]}
          />

          <Field
            label="Certificate profile"
            hint={
              profiles
                ? "The certificate type the CA will issue."
                : "Load the profiles this account can issue."
            }
          >
            <div className="path-row">
              <select
                value={productCode}
                disabled={!profiles || profiles.length === 0}
                onChange={(event) => chooseProfile(event.target.value)}
              >
                <option value="">
                  {profiles ? "Use the configured default" : "Not loaded"}
                </option>
                {(profiles ?? []).map((profile) => (
                  <option key={profile.id} value={profile.id}>
                    {profile.name} ({profile.id})
                  </option>
                ))}
              </select>
              <button type="button" className="ghost" disabled={loadingProfiles} onClick={load}>
                {loadingProfiles ? "Loading…" : "Load profiles"}
              </button>
            </div>
          </Field>

          <Field
            label="Term (days)"
            hint={
              selected
                ? `${selected.name} allows ${terms.join(", ")} days.`
                : "Pick a profile to see the terms it allows."
            }
          >
            <select
              value={termDays}
              disabled={terms.length === 0}
              onChange={(event) => setTermDays(event.target.value)}
            >
              <option value="">
                {terms.length === 0 ? "Profile default" : "Profile default"}
              </option>
              {terms.map((term) => (
                <option key={term} value={term}>
                  {term} days
                </option>
              ))}
            </select>
          </Field>

          <Field label="Description" hint="Optional label shown in the CA console.">
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>

          <PathField
            label="Also save request ID to"
            hint="Optional — the ID is remembered here and offered on the Collect screen."
            value={out}
            onChange={setOut}
            mode="save"
          />

          <div className="actions">
            <SubmitButton busy={op.busy} label="Submit CSR" disabled={!csr} />
          </div>
        </form>
      </div>
      <div className="pane">
        {profileError ? (
          <Banner tone="danger" title="Could not load profiles">
            {profileError}
          </Banner>
        ) : null}
        {op.error ? (
          <Banner tone="danger" title="Submission failed">
            {op.error}
          </Banner>
        ) : null}
        {op.outcome?.outcome === "caCsrSubmitted" ? (
          <Banner
            tone="ok"
            title="CSR submitted"
            aside={<CopyButton text={op.outcome.requestId} label="Copy ID" />}
          >
            Request ID <code>{op.outcome.requestId}</code>
            {op.outcome.path ? (
              <>
                {" "}
                saved to <code>{op.outcome.path}</code>
              </>
            ) : (
              " — saved here and available on the Collect screen."
            )}
          </Banner>
        ) : null}
        {!op.error && !op.outcome && !profileError ? (
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
  const [format, setFormat] = useState("chain");
  const [past, setPast] = useState<CaRequestRecord[]>([]);
  const op = useOp();

  // Past submissions come from the same workspace state the CLI writes, so an
  // ID submitted from a terminal shows up here too.
  useEffect(() => {
    loadSession()
      .then((session) => setPast(session.caRequests))
      .catch(() => {
        /* First run with no state file is normal. */
      });
  }, [op.outcome]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    await op.run({ op: "caCollectCert", requestId, out, format });
  }

  return (
    <div className="main-body">
      <div className="pane">
        <form className="form" onSubmit={submit}>
          {past.length > 0 ? (
            <Field
              label="Recent submissions"
              hint="Picks the ID below. Requests submitted elsewhere can be typed in directly."
            >
              <select
                value={past.some((record) => record.request_id === requestId) ? requestId : ""}
                onChange={(event) => setRequestId(event.target.value)}
              >
                <option value="">Choose a past request…</option>
                {past.map((record) => (
                  <option key={record.request_id} value={record.request_id}>
                    {record.request_id}
                    {record.common_name ? ` — ${record.common_name}` : ""}
                    {record.description ? ` (${record.description})` : ""}
                  </option>
                ))}
              </select>
            </Field>
          ) : null}

          <Field label="Request ID" hint="Returned when the CSR was submitted.">
            <input
              type="text"
              value={requestId}
              spellCheck={false}
              onChange={(e) => setRequestId(e.target.value)}
            />
          </Field>

          <Field label="Format" hint="Matches the CA console's Retrieve menu.">
            <select
              value={format}
              onChange={(event) => {
                setFormat(event.target.value);
                // PKCS#7 lands in a .p7b, not a .pem — retarget a filename the
                // user has not deliberately chosen.
                setOut((current) => retargetExtension(current, event.target.value));
              }}
            >
              {COLLECT_FORMATS.map((option) => (
                <option key={option.token} value={option.token}>
                  {option.label}
                </option>
              ))}
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
            <code>{op.outcome.path}</code> ({formatLabel(op.outcome.format)})
          </Banner>
        ) : null}
        {!op.error && !op.outcome ? (
          <Empty
            title="Nothing collected"
            detail="Downloads an issued certificate. 'Certificate (w/ chain)' is usually what a server wants."
          />
        ) : null}
      </div>
    </div>
  );
}

function formatLabel(token: string): string {
  return COLLECT_FORMATS.find((option) => option.token === token)?.label ?? token;
}

/** Swap a path's extension to suit the chosen format, leaving other paths alone. */
function retargetExtension(path: string, token: string): string {
  if (!path) return path;
  const wanted = token.startsWith("pkcs7") ? "p7b" : "pem";
  return path.replace(/\.(pem|p7b|crt|cer)$/i, `.${wanted}`);
}
