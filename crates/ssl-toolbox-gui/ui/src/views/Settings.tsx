import { useCallback, useEffect, useState } from "react";
import { Badge, Banner, Field, Panel, SecretField, SubmitButton } from "../components";
import { runOp } from "../lib/api";
import { clearSecrets, useSecret } from "../lib/secrets";
import type { CaSettingsView, CredentialStatus } from "../lib/types";

/**
 * CA configuration, including the credentials that used to require a `.env`
 * file next to a terminal-run CLI.
 *
 * That arrangement could never work here: an app launched from Finder or the
 * Start menu inherits no shell environment, so the CA screens had no way to
 * authenticate at all. Credentials now go into an encrypted vault in
 * `~/.ssl-toolbox`, which both front-ends read.
 *
 * Two rules this screen enforces:
 *
 * 1. **Secrets travel one way.** A client secret and a vault passphrase go out
 *    to Rust and never come back — the backend cannot return them. Fields are
 *    cleared on submit per `lib/secrets.ts`.
 * 2. **The client ID is not displayed.** Only its length crosses the boundary
 *    (ARCHITECTURE.md §11.3 rule 1). "Configured, 32 characters" is the most
 *    this screen is allowed to say about a stored identity.
 */
export function SettingsView() {
  const [view, setView] = useState<CaSettingsView | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [apiBase, setApiBase] = useState("");
  const [orgId, setOrgId] = useState("");
  const [productCode, setProductCode] = useState("");
  const [tokenUrl, setTokenUrl] = useState("");
  const [clientId, setClientId] = useState("");

  const clientSecret = useSecret();
  const vaultPassphrase = useSecret();
  const confirmPassphrase = useSecret();
  const unlockPassphrase = useSecret();

  const applyView = useCallback((next: CaSettingsView) => {
    setView(next);
    setApiBase(next.apiBase);
    setOrgId(next.orgId);
    setProductCode(next.productCode);
    setTokenUrl(next.tokenUrl);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const outcome = await runOp({ op: "caLoadSettings" });
      if (outcome.outcome === "caSettingsLoaded") applyView(outcome);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    }
  }, [applyView]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  /**
   * Run one settings action, keeping exactly one result message on screen.
   *
   * Each action reports separately so a failed "Test connection" does not erase
   * the confirmation that the settings above it saved correctly.
   */
  async function act(name: string, run: () => Promise<string | null>) {
    setBusy(name);
    setError(null);
    setNotice(null);
    try {
      const message = await run();
      if (message) setNotice(message);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setBusy(null);
      await refresh();
    }
  }

  async function saveSettings(event: React.FormEvent) {
    event.preventDefault();
    await act("settings", async () => {
      const outcome = await runOp({
        op: "caSaveSettings",
        apiBase,
        orgId,
        productCode,
        tokenUrl,
      });
      if (outcome.outcome !== "caSettingsSaved") return "Settings saved.";
      return outcome.shadowedBy
        ? `Saved to ${outcome.path}, but ${outcome.shadowedBy} overrides it in this directory.`
        : `Saved to ${outcome.path}.`;
    });
  }

  async function storeCredentials(event: React.FormEvent) {
    event.preventDefault();
    if (vaultPassphrase.value !== confirmPassphrase.value) {
      setError("Vault passphrases do not match.");
      return;
    }
    await act("credentials", async () => {
      try {
        await runOp({
          op: "caStoreCredentials",
          clientId,
          clientSecret: clientSecret.value,
          vaultPassphrase: vaultPassphrase.value,
        });
        setClientId("");
        return "Credentials encrypted and saved. They are unlocked for this session.";
      } finally {
        // A throw must not leave a secret in a mounted component.
        clearSecrets(clientSecret, vaultPassphrase, confirmPassphrase);
      }
    });
  }

  async function unlock(event: React.FormEvent) {
    event.preventDefault();
    await act("unlock", async () => {
      try {
        await runOp({ op: "caUnlockCredentials", vaultPassphrase: unlockPassphrase.value });
        return "Credentials unlocked for this session.";
      } finally {
        clearSecrets(unlockPassphrase);
      }
    });
  }

  async function testConnection() {
    await act("test", async () => {
      const outcome = await runOp({ op: "caTestConnection" });
      if (outcome.outcome !== "caConnectionVerified") return "Authentication succeeded.";
      const where =
        outcome.source === "environment" ? "environment variables" : "the credential vault";
      return `Authenticated with ${outcome.provider} using credentials from ${where}.`;
    });
  }

  const credentials = view?.credentials;
  const envOverride = credentials?.environmentOverride ?? false;
  const locked = !!credentials && !credentials.unlocked && credentials.vaultPresent && !envOverride;

  return (
    <div className="main-body">
      <div className="pane">
        <Panel title="Credentials" aside={<CredentialBadge status={credentials} />}>
          {credentials?.problem ? (
            <Banner tone="danger" title="Credential configuration is unusable">
              {credentials.problem}
            </Banner>
          ) : null}

          {envOverride ? (
            <Banner tone="warn" title="Environment variables are in control">
              <code className="mono">SCM_CLIENT_ID</code> and{" "}
              <code className="mono">SCM_CLIENT_SECRET</code> are set in this process and take
              precedence over anything stored here. Unset them to use the vault.
            </Banner>
          ) : null}

          {locked ? (
            <form className="form" onSubmit={unlock}>
              <div className="small muted">
                Credentials are stored but locked. Unlock them once per app launch.
              </div>
              <SecretField
                label="Vault passphrase"
                value={unlockPassphrase.value}
                onChange={unlockPassphrase.set}
              />
              <div className="actions">
                <SubmitButton
                  busy={busy === "unlock"}
                  label="Unlock"
                  disabled={!unlockPassphrase.value}
                />
              </div>
            </form>
          ) : null}

          <form className="form" onSubmit={storeCredentials}>
            <div className="small muted">
              {credentials?.vaultPresent
                ? "Saving replaces the stored credentials."
                : "Stored encrypted in ~/.ssl-toolbox/credentials.vault."}
            </div>
            <Field label="Client ID" hint="The OAuth client the CA issued to you.">
              <input
                type="text"
                value={clientId}
                spellCheck={false}
                autoComplete="off"
                onChange={(event) => setClientId(event.target.value)}
              />
            </Field>
            <SecretField
              label="Client secret"
              value={clientSecret.value}
              onChange={clientSecret.set}
            />
            <SecretField
              label="Vault passphrase"
              hint="Encrypts the credentials at rest. There is no recovery if you lose it."
              value={vaultPassphrase.value}
              onChange={vaultPassphrase.set}
            />
            <SecretField
              label="Confirm vault passphrase"
              value={confirmPassphrase.value}
              onChange={confirmPassphrase.set}
            />
            <div className="actions">
              <SubmitButton
                busy={busy === "credentials"}
                label="Save credentials"
                disabled={!clientId || !clientSecret.value || !vaultPassphrase.value}
              />
              <button
                type="button"
                className="ghost"
                disabled={busy !== null || !credentials?.activeSource}
                onClick={testConnection}
              >
                Test connection
              </button>
              {credentials?.unlocked ? (
                <button
                  type="button"
                  className="ghost"
                  disabled={busy !== null}
                  onClick={() => act("lock", async () => {
                    await runOp({ op: "caLockCredentials" });
                    return "Credentials locked.";
                  })}
                >
                  Lock
                </button>
              ) : null}
              {credentials?.vaultPresent ? (
                <button
                  type="button"
                  className="ghost"
                  disabled={busy !== null}
                  onClick={() => act("clear", async () => {
                    await runOp({ op: "caClearCredentials" });
                    return "Credential vault deleted.";
                  })}
                >
                  Delete vault
                </button>
              ) : null}
            </div>
          </form>
        </Panel>

        <Panel title="CA endpoint">
          <form className="form" onSubmit={saveSettings}>
            <Field label="API base URL">
              <input
                type="text"
                value={apiBase}
                spellCheck={false}
                placeholder="https://admin.enterprise.sectigo.com"
                onChange={(event) => setApiBase(event.target.value)}
              />
            </Field>
            <Field label="Token URL" hint="The identity provider's OAuth token endpoint.">
              <input
                type="text"
                value={tokenUrl}
                spellCheck={false}
                placeholder="https://auth.example.com/.../protocol/openid-connect/token"
                onChange={(event) => setTokenUrl(event.target.value)}
              />
            </Field>
            <Field label="Organisation ID" hint="Required to list profiles or submit a CSR.">
              <input
                type="text"
                value={orgId}
                spellCheck={false}
                onChange={(event) => setOrgId(event.target.value)}
              />
            </Field>
            <Field label="Default product code" hint="Optional — the profile used when none is given.">
              <input
                type="text"
                value={productCode}
                spellCheck={false}
                onChange={(event) => setProductCode(event.target.value)}
              />
            </Field>
            <div className="actions">
              <SubmitButton busy={busy === "settings"} label="Save settings" />
            </div>
          </form>
        </Panel>
      </div>

      <div className="pane">
        {error ? (
          <Banner tone="danger" title="Settings error">
            {error}
          </Banner>
        ) : null}
        {notice ? (
          <Banner tone="ok" title="Done">
            {notice}
          </Banner>
        ) : null}

        {view ? <WhereSettingsComeFrom view={view} /> : null}
      </div>
    </div>
  );
}

function CredentialBadge({ status }: { status: CredentialStatus | undefined }) {
  if (!status) return <Badge tone="neutral">Loading</Badge>;
  if (status.problem) return <Badge tone="danger">Misconfigured</Badge>;
  if (status.activeSource === "environment") return <Badge tone="warn">From environment</Badge>;
  if (status.activeSource === "vault") return <Badge tone="ok">Unlocked</Badge>;
  if (status.vaultPresent) return <Badge tone="warn">Locked</Badge>;
  return <Badge tone="neutral">Not configured</Badge>;
}

/**
 * Where each value actually comes from.
 *
 * Configuration resolves through layers (ARCHITECTURE.md §3), so a saved value
 * can be correct and still not be the one in use. Showing the layers turns
 * "why didn't my change take effect" into something answerable on screen.
 */
function WhereSettingsComeFrom({ view }: { view: CaSettingsView }) {
  const { credentials } = view;

  return (
    <Panel title="Where these settings come from">
      <dl className="kv">
        <dt>Provider</dt>
        <dd>{view.provider ?? "None — built without a CA plugin"}</dd>

        <dt>Settings file</dt>
        <dd>{view.configPath ?? "Unavailable"}</dd>

        {view.shadowedBy ? (
          <>
            <dt>Overridden by</dt>
            <dd>{view.shadowedBy} — a project-scope file in the current directory</dd>
          </>
        ) : null}

        {view.environmentOverrides.length > 0 ? (
          <>
            <dt>Environment</dt>
            <dd>{view.environmentOverrides.join(", ")} — these win over the settings file</dd>
          </>
        ) : null}

        <dt>Credential vault</dt>
        <dd>
          {credentials.vaultPath ?? "Unavailable"}
          {credentials.vaultPresent ? "" : " (not created yet)"}
        </dd>

        <dt>Client ID</dt>
        <dd>
          {credentials.clientIdLength === null
            ? "Not configured"
            : `${credentials.clientIdLength} characters — the value is never shown`}
        </dd>
      </dl>

      <div className="small muted">
        Credentials resolve in one order: environment variables first, then the encrypted vault.
        The vault is encrypted with your passphrase, so unlocking it once per app launch is
        required — nothing on disk can unlock it on your behalf.
      </div>
    </Panel>
  );
}
