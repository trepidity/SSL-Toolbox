/**
 * Wire types mirroring `ssl-toolbox-ops`.
 *
 * Nothing type-checks the JSON crossing the webview IPC boundary, so these
 * declarations are a hand-maintained contract. The Rust side pins the same
 * shape in `crates/ssl-toolbox-ops/tests/ops_behavior.rs`
 * (`op_requests_deserialize_from_the_camel_case_wire_shape`) — if you rename a
 * field here, rename it there too or the app breaks silently at runtime.
 */

export type EndpointProtocol = "https" | "ldaps" | "smtp" | "sqlServer";

export type CertFormat = "Pem" | "Der" | "Pkcs12" | "Pkcs7" | "Base64" | "Unknown";

export interface CertDetails {
  common_name: string;
  sans: string[];
  not_before: string;
  not_after: string;
  issuer: string;
  signature_algorithm: string;
  public_key_bits: number;
  serial_number: string;
  sha1_fingerprint: string;
  sha256_fingerprint: string;
}

export interface PrivateKeySummary {
  present: boolean;
  algorithm: string;
  key_size_bits: number;
  security_bits: number;
  matches_leaf_certificate: boolean;
}

export interface PfxDetails {
  cert_chain: CertDetails[];
  private_key: PrivateKeySummary;
}

export interface ValidationResult {
  passed: boolean;
  message: string;
}

export interface CertValidation {
  hostname_match: ValidationResult | null;
  expiry_check: ValidationResult | null;
  chain_valid: ValidationResult | null;
}

export interface CipherInfo {
  name: string;
  bits: number;
  protocol: string;
}

export interface TlsVersionProbeResult {
  label: string;
  supported: boolean;
}

export interface TlsCipherScanResult {
  protocol: string;
  tested_cipher_count: number;
  supported_ciphers: CipherInfo[];
}

export interface TlsCheckResult {
  host: string;
  port: number;
  cipher: CipherInfo;
  cert_chain: CertDetails[];
  cert_chain_pem: string[];
  version_support: TlsVersionProbeResult[];
  cipher_scan: TlsCipherScanResult[];
  validation: CertValidation | null;
  chain_sent_out_of_order: boolean;
}

export interface LdapAttribute {
  name: string;
  values: string[];
}

export interface LdapConfigCheckResult {
  host: string;
  port: number;
  authentication: string;
  attributes: LdapAttribute[];
}

export interface ValidationComparison {
  previous_timestamp_utc: string | null;
  changes: string[];
}

export interface ValidationAuditEntry {
  timestamp_secs: number;
  timestamp_utc: string;
  kind: ActionKind;
  host: string;
  port: number;
  certificate_validation_requested: boolean;
  full_scan: boolean;
  status: "Success" | "Failure";
  error: string | null;
  comparison: ValidationComparison;
}

export interface EndpointVerification {
  protocol: EndpointProtocol;
  host: string;
  port: number;
  result: TlsCheckResult;
  audit: ValidationAuditEntry;
  ldapConfig: LdapConfigCheckResult | null;
  ldapConfigError: string | null;
  exportedCerts: string[];
}

export interface ConfigInputs {
  common_name: string;
  country: string;
  state: string;
  locality: string;
  organization: string;
  org_unit: string;
  email: string;
  sans: SanName[];
  key_size: number;
  extended_key_usage: string;
}

export interface CsrDefaults {
  country: string;
  state: string;
  locality: string;
  organization: string;
  org_unit: string;
  email: string;
}

export type ActionKind =
  | "CreateKey"
  | "Generate"
  | "CreatePfx"
  | "CreateLegacyPfx"
  | "NewConfig"
  | "ConfigFromExisting"
  | "ViewCert"
  | "ViewCsr"
  | "ViewPfx"
  | "VerifyHttps"
  | "VerifyLdaps"
  | "VerifySmtp"
  | "VerifySqlServer"
  | "Convert"
  | "Identify"
  | "CaSubmit"
  | "CaProfiles"
  | "CaSettings"
  | "CaCredentials"
  | "CaSearch";

export interface JobRecord {
  kind: ActionKind;
  summary: string;
  inputs: Record<string, string>;
  outputs: Record<string, string>;
  replay_data: Record<string, string>;
  profile: string | null;
  transient: boolean;
  timestamp_secs: number;
}

export interface WorkflowMemory {
  config: string | null;
  key: string | null;
  csr: string | null;
  cert: string | null;
  chain: string | null;
  pfx: string | null;
  legacy_pfx: string | null;
  https_host: string | null;
  ldaps_host: string | null;
  smtp_host: string | null;
  sql_server_host: string | null;
  active_profile: string | null;
}

export interface SessionState {
  workflow: WorkflowMemory;
  recentJobs: JobRecord[];
  csrDefaults: CsrDefaults;
  caRequests: CaRequestRecord[];
}

export interface WorkspaceFile {
  path: string;
  kind: string;
}

export interface WorkspaceSnapshot {
  root: string;
  files: WorkspaceFile[];
}

export interface ActionInfo {
  kind: ActionKind;
  alias: string;
  title: string;
}

/** Optional LDAP RootDSE probe attached to an LDAPS verification. */
export interface LdapConfigTest {
  port?: number | null;
  bindDn?: string | null;
  bindPassword?: string | null;
}

/**
 * Discriminated by `op`, matching serde's `#[serde(tag = "op")]`.
 * Fields typed `string` that carry a passphrase are `Secret` on the Rust side:
 * one-way, never returned.
 */
/**
 * A GeneralName choice from RFC 5280 §4.2.1.6, limited to the seven OpenSSL's
 * config syntax can express. `x400Address` and `ediPartyName` are excluded
 * because `openssl.cnf` has no syntax for them at all.
 */
/**
 * Where an inspection reads from. Mirrors `InputSource` in Rust, which is a
 * serde-tagged enum — the `kind` discriminant is part of the wire shape.
 */
export type InputSource = { kind: "path"; path: string } | { kind: "text"; text: string };

/** A CSR previously submitted to a CA, remembered so its ID can be offered back. */
export interface CaRequestRecord {
  request_id: string;
  common_name: string;
  description: string;
  profile: string;
  csr_path: string;
  timestamp_secs: number;
}

/**
 * The retrieve formats the CA offers, matching its console menu so a value
 * picked here means the same thing as one picked in the browser.
 *
 * Tokens are the contract with `CollectFormat::parse` in Rust.
 */
export const COLLECT_FORMATS: { token: string; label: string }[] = [
  { token: "cert", label: "Certificate only, PEM encoded" },
  { token: "cert-issuer-after", label: "Certificate (w/ issuer after), PEM encoded" },
  { token: "chain", label: "Certificate (w/ chain), PEM encoded" },
  { token: "pkcs7", label: "PKCS#7" },
  { token: "pkcs7-pem", label: "PKCS#7, PEM encoded" },
  { token: "intermediates", label: "Intermediate(s)/Root only, PEM encoded" },
  { token: "root-first", label: "Root/Intermediate(s) only, PEM encoded" },
];

export type SanKind = "dns" | "ip" | "email" | "uri" | "registeredId" | "otherName" | "dirName";

export interface SanName {
  kind: SanKind;
  value: string;
}

/** Label and `[alt_names]` key for each type, in the order the UI offers them. */
export const SAN_KINDS: { kind: SanKind; label: string; configKey: string; placeholder: string }[] = [
  { kind: "dns", label: "DNS", configKey: "DNS", placeholder: "alt.example.com" },
  { kind: "ip", label: "IP address", configKey: "IP", placeholder: "10.0.0.5" },
  { kind: "email", label: "Email", configKey: "email", placeholder: "admin@example.com" },
  { kind: "uri", label: "URI", configKey: "URI", placeholder: "https://example.com/" },
  {
    kind: "registeredId",
    label: "Registered ID",
    configKey: "RID",
    placeholder: "1.3.6.1.5.5.7.3.1",
  },
  {
    kind: "otherName",
    label: "Other name",
    configKey: "otherName",
    placeholder: "1.3.6.1.4.1.311.20.2.3;UTF8:user@example.com",
  },
  {
    kind: "dirName",
    label: "Directory name",
    configKey: "dirName",
    placeholder: "CN=Example,O=Example Org",
  },
];

/**
 * What the toolbox could read out of an existing config. Every field is optional
 * because someone else wrote the file — see `ConfigSummary` in Rust.
 */
export interface ConfigSummary {
  commonName: string | null;
  country: string | null;
  state: string | null;
  locality: string | null;
  organization: string | null;
  orgUnit: string | null;
  email: string | null;
  keySize: number | null;
  extendedKeyUsage: string | null;
  sans: SanName[];
  sections: string[];
  warnings: string[];
}

export type OpRequest =
  | { op: "createKey"; out: string; password: string }
  | {
      op: "generateCsr";
      conf: string;
      key: string;
      csr: string;
      keyPassword: string;
      createKeyIfMissing?: boolean;
    }
  | {
      op: "createPfx";
      key: string;
      cert: string;
      chain?: string | null;
      out: string;
      keyPassword: string;
      pfxPassword: string;
      legacy?: boolean;
    }
  | {
      op: "convertPfxToLegacy";
      input: string;
      out: string;
      inputPassword: string;
      outputPassword: string;
    }
  | { op: "generateConfig"; inputs: ConfigInputs; out: string }
  | { op: "generateConfigFromCertOrCsr"; input: string; out: string; isCsr?: boolean }
  | { op: "loadConfig"; path: string }
  | { op: "saveConfig"; path: string; text: string }
  | { op: "inspectCert"; input: InputSource }
  | { op: "inspectCsr"; input: InputSource }
  | { op: "inspectPfx"; input: string; password: string }
  | {
      op: "verifyEndpoint";
      protocol: EndpointProtocol;
      host: string;
      port?: number | null;
      verify?: boolean;
      fullScan?: boolean;
      exportCertsDir?: string | null;
      ldapConfigTest?: LdapConfigTest | null;
    }
  | { op: "convertFormat"; input: string; output: string; format: string }
  | { op: "identifyFormat"; input: string }
  | { op: "caListProfiles"; debug?: boolean }
  | {
      op: "caSubmitCsr";
      csr: string;
      /** Optional: the ID is recorded in the workspace regardless. */
      out?: string | null;
      description?: string | null;
      productCode?: string | null;
      termDays?: number | null;
      debug?: boolean;
    }
  | {
      op: "caCollectCert";
      requestId: string;
      out: string;
      format: string;
      debug?: boolean;
    }
  | {
      op: "caSearchCertificates";
      commonName?: string | null;
      subjectAlternativeName?: string | null;
      serialNumber?: string | null;
      status?: string | null;
      profileId?: string | null;
      size?: number | null;
      position?: number | null;
      includeDates?: boolean;
      debug?: boolean;
    }
  | { op: "caCertificateDetails"; certificateId: string; debug?: boolean }
  | { op: "caListRequests" }
  | { op: "caLoadSettings" }
  | {
      op: "caSaveSettings";
      apiBase: string;
      orgId: string;
      productCode: string;
      tokenUrl: string;
    }
  | {
      op: "caStoreCredentials";
      clientId: string;
      clientSecret: string;
      vaultPassphrase: string;
    }
  | { op: "caUnlockCredentials"; vaultPassphrase: string }
  | { op: "caLockCredentials" }
  | { op: "caClearCredentials" }
  | { op: "caTestConnection"; debug?: boolean };

/** One row of a certificate search. `id` is what the Collect screen takes. */
export interface CertificateSummary {
  id: string;
  common_name: string;
  subject_alternative_names: string[];
  serial_number: string;
  status: string | null;
  requested: string | null;
  expires: string | null;
}

/** Fields are optional because this is a vendor payload — render gaps, not errors. */
export interface CertificateDetails {
  id: string;
  common_name: string;
  subject_alternative_names: string[];
  serial_number: string;
  status: string | null;
  profile: string | null;
  term_days: number | null;
  requested: string | null;
  expires: string | null;
  requester: string | null;
  comments: string | null;
  key_algorithm: string | null;
}

export interface CertProfile {
  id: string;
  name: string;
  description: string | null;
  terms: number[];
}

/** Discriminated by `outcome`, matching serde's `#[serde(tag = "outcome")]`. */
export type OpOutcome =
  | { outcome: "keyCreated"; path: string }
  | {
      outcome: "csrGenerated";
      csrPath: string;
      csrPem: string;
      keyPath: string;
      keyCreated: boolean;
    }
  | { outcome: "pfxCreated"; path: string; legacy: boolean }
  | { outcome: "configWritten"; path: string }
  | { outcome: "configLoaded"; path: string; text: string; summary: ConfigSummary }
  | { outcome: "configSaved"; path: string; backup: string | null; summary: ConfigSummary }
  | { outcome: "certInspected"; path: string; chain: CertDetails[] }
  | { outcome: "csrInspected"; path: string; commonName: string; sans: string[]; pem: string }
  | { outcome: "pfxInspected"; path: string; details: PfxDetails }
  | ({ outcome: "endpointVerified" } & EndpointVerification)
  | { outcome: "formatConverted"; output: string; format: string }
  | { outcome: "formatIdentified"; path: string; format: CertFormat; description: string }
  | { outcome: "caProfilesListed"; provider: string; profiles: CertProfile[] }
  | { outcome: "caCsrSubmitted"; requestId: string; path: string | null }
  | { outcome: "caRequestsListed"; requests: CaRequestRecord[] }
  | {
      outcome: "caCertificatesFound";
      provider: string;
      certificates: CertificateSummary[];
      position: number;
      mayHaveMore: boolean;
    }
  | { outcome: "caCertificateLoaded"; provider: string; certificate: CertificateDetails }
  | { outcome: "caCertCollected"; path: string; format: string }
  | ({ outcome: "caSettingsLoaded" } & CaSettingsView)
  | { outcome: "caSettingsSaved"; path: string; shadowedBy: string | null }
  | { outcome: "caCredentialsChanged"; status: CredentialStatus }
  | { outcome: "caConnectionVerified"; provider: string; source: CredentialSource };

/** Which configuration layer is currently supplying CA credentials. */
export type CredentialSource = "environment" | "vault";

/**
 * What the UI is allowed to know about the stored credentials.
 *
 * The client ID is deliberately absent — only its length crosses the boundary.
 * See `CredentialStatus` in Rust and ARCHITECTURE.md §11.3 rule 1.
 */
export interface CredentialStatus {
  environmentOverride: boolean;
  vaultPresent: boolean;
  unlocked: boolean;
  activeSource: CredentialSource | null;
  clientIdLength: number | null;
  vaultPath: string | null;
  /** Why the current configuration is unusable, when it is. */
  problem: string | null;
}

export interface CaSettingsView {
  provider: string | null;
  apiBase: string;
  orgId: string;
  productCode: string;
  tokenUrl: string;
  configPath: string | null;
  shadowedBy: string | null;
  environmentOverrides: string[];
  credentials: CredentialStatus;
}
