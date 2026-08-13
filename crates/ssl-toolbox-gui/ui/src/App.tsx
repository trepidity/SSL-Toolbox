import { useEffect, useMemo, useState } from "react";
import { loadSession } from "./lib/api";
import type { CsrDefaults, JobRecord } from "./lib/types";
import {
  ConfigFromExistingView,
  CreateKeyView,
  GenerateCsrView,
  NewConfigView,
} from "./views/Generate";
import { ConvertView, CreatePfxView, IdentifyView, LegacyPfxView } from "./views/Bundle";
import { EditConfigView } from "./views/ConfigEdit";
import { InspectCertView, InspectCsrView, InspectPfxView } from "./views/Inspect";
import { VerifyView } from "./views/Verify";
import { HistoryView } from "./views/History";
import { CaCollectView, CaProfilesView, CaSubmitView } from "./views/Ca";

interface NavItem {
  id: string;
  glyph: string;
  label: string;
  title: string;
  subtitle: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV: NavGroup[] = [
  {
    label: "Create",
    items: [
      {
        id: "key",
        glyph: "K",
        label: "Private key",
        title: "Create private key",
        subtitle: "Generate an encrypted RSA-2048 key",
      },
      {
        id: "csr",
        glyph: "R",
        label: "CSR",
        title: "Generate CSR",
        subtitle: "Build a signing request from an OpenSSL config",
      },
      {
        id: "newconfig",
        glyph: "C",
        label: "New config",
        title: "New OpenSSL config",
        subtitle: "Describe a subject and write a .cnf",
      },
      {
        id: "editconfig",
        glyph: "E",
        label: "Edit config",
        title: "View / edit OpenSSL config",
        subtitle: "Open a .cnf as text, see what it declares, save it back",
      },
      {
        id: "configfrom",
        glyph: "C",
        label: "Config from cert",
        title: "Config from certificate",
        subtitle: "Reuse an existing certificate's subject for renewal",
      },
    ],
  },
  {
    label: "Bundle",
    items: [
      {
        id: "pfx",
        glyph: "P",
        label: "Build PFX",
        title: "Build PFX",
        subtitle: "Package a key, certificate, and chain into PKCS#12",
      },
      {
        id: "legacy",
        glyph: "L",
        label: "Legacy PFX",
        title: "Legacy PFX",
        subtitle: "Re-encrypt a PFX with TripleDES-SHA1 for old systems",
      },
    ],
  },
  {
    label: "Inspect",
    items: [
      {
        id: "viewcert",
        glyph: "◦",
        label: "Certificate",
        title: "Inspect certificate",
        subtitle: "Subject, issuer, validity, SANs, fingerprints",
      },
      {
        id: "viewcsr",
        glyph: "◦",
        label: "CSR",
        title: "Inspect CSR",
        subtitle: "Confirm the subject and SANs before submitting",
      },
      {
        id: "viewpfx",
        glyph: "◦",
        label: "PFX",
        title: "Inspect PFX",
        subtitle: "See what a bundle actually contains",
      },
      {
        id: "identify",
        glyph: "?",
        label: "Identify file",
        title: "Identify file format",
        subtitle: "Detect PEM, DER, PKCS#12, and PKCS#7 from content",
      },
    ],
  },
  {
    label: "Verify",
    items: [
      {
        id: "https",
        glyph: "→",
        label: "HTTPS",
        title: "Verify HTTPS endpoint",
        subtitle: "Check the certificate and TLS configuration of a web server",
      },
      {
        id: "ldaps",
        glyph: "→",
        label: "LDAPS",
        title: "Verify LDAPS endpoint",
        subtitle: "Check a directory server's TLS, and optionally its RootDSE",
      },
      {
        id: "smtp",
        glyph: "→",
        label: "SMTP",
        title: "Verify SMTP endpoint",
        subtitle: "Check the certificate presented after STARTTLS",
      },
    ],
  },
  {
    label: "Certificate Authority",
    items: [
      {
        id: "caprofiles",
        glyph: "A",
        label: "Profiles",
        title: "CA certificate profiles",
        subtitle: "List the certificate types this CA account can issue",
      },
      {
        id: "casubmit",
        glyph: "A",
        label: "Submit CSR",
        title: "Submit CSR to CA",
        subtitle: "Send a signing request and record the returned request ID",
      },
      {
        id: "cacollect",
        glyph: "A",
        label: "Collect cert",
        title: "Collect signed certificate",
        subtitle: "Download an issued certificate by its request ID",
      },
    ],
  },
  {
    label: "Utilities",
    items: [
      {
        id: "convert",
        glyph: "⇄",
        label: "Convert format",
        title: "Convert certificate format",
        subtitle: "Translate between PEM, DER, and Base64",
      },
      {
        id: "history",
        glyph: "≡",
        label: "History",
        title: "History",
        subtitle: "Recent jobs and the endpoint validation log",
      },
    ],
  },
];

const EMPTY_DEFAULTS: CsrDefaults = {
  country: "",
  state: "",
  locality: "",
  organization: "",
  org_unit: "",
  email: "",
};

export default function App() {
  const [active, setActive] = useState("https");
  const [defaults, setDefaults] = useState<CsrDefaults>(EMPTY_DEFAULTS);
  const [recentJobs, setRecentJobs] = useState<JobRecord[]>([]);

  // Workflow memory and org defaults are shared with the CLI via
  // ~/.ssl-toolbox, so they are read once at startup.
  useEffect(() => {
    loadSession()
      .then((session) => {
        setDefaults(session.csrDefaults);
        setRecentJobs(session.recentJobs);
      })
      .catch(() => {
        /* First run with no state file is normal. */
      });
  }, [active]);

  const current = useMemo(
    () => NAV.flatMap((group) => group.items).find((item) => item.id === active) ?? NAV[0].items[0],
    [active],
  );

  return (
    <div className="app">
      <nav className="rail">
        <div className="rail-brand">
          <strong>SSL Toolbox</strong>
          <span>v2.0.5</span>
        </div>
        {NAV.map((group) => (
          <div className="rail-group" key={group.label}>
            <div className="rail-group-label">{group.label}</div>
            {group.items.map((item) => (
              <button
                type="button"
                key={item.id}
                className="rail-item"
                aria-current={item.id === active}
                onClick={() => setActive(item.id)}
              >
                <span className="glyph">{item.glyph}</span>
                {item.label}
              </button>
            ))}
          </div>
        ))}
      </nav>

      <main className="main">
        <header className="main-header">
          <h1>{current.title}</h1>
          <p>{current.subtitle}</p>
        </header>

        {active === "key" ? <CreateKeyView /> : null}
        {active === "csr" ? <GenerateCsrView /> : null}
        {active === "newconfig" ? <NewConfigView defaults={defaults} /> : null}
        {active === "editconfig" ? <EditConfigView /> : null}
        {active === "configfrom" ? <ConfigFromExistingView /> : null}
        {active === "pfx" ? <CreatePfxView /> : null}
        {active === "legacy" ? <LegacyPfxView /> : null}
        {active === "viewcert" ? <InspectCertView /> : null}
        {active === "viewcsr" ? <InspectCsrView /> : null}
        {active === "viewpfx" ? <InspectPfxView /> : null}
        {active === "identify" ? <IdentifyView /> : null}
        {active === "https" ? <VerifyView protocol="https" key="https" /> : null}
        {active === "ldaps" ? <VerifyView protocol="ldaps" key="ldaps" /> : null}
        {active === "smtp" ? <VerifyView protocol="smtp" key="smtp" /> : null}
        {active === "caprofiles" ? <CaProfilesView /> : null}
        {active === "casubmit" ? <CaSubmitView /> : null}
        {active === "cacollect" ? <CaCollectView /> : null}
        {active === "convert" ? <ConvertView /> : null}
        {active === "history" ? <HistoryView recentJobs={recentJobs} /> : null}
      </main>
    </div>
  );
}
