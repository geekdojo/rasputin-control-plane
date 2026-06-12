'use client';

// /trust — unauthenticated first-run landing page, served over plain HTTP
// by the api's bootstrap listener (an operator browsing http://rasputin.local
// is 302'd here). Walks the operator through installing this installation's
// certificate once per device, then hands off to the HTTPS login page where
// the passkey ceremony has the secure context it needs.
//
// Copy rules: vendor-neutral — "certificate", "secure connection", "passkey";
// no backend tech names in user-visible strings.

import { ArrowRight, Download, ShieldCheck } from 'lucide-react';
import type { CSSProperties, ReactNode } from 'react';
import { useEffect, useState } from 'react';
import { CopyButton, DIM, FG, HAIR, Hint, PANEL, SectionLabel } from '../../components/kit';
import { ACCENT, accentA, MONO } from '../../components/ui-theme';

export default function TrustPage() {
  // Fallback for the static prerender; replaced with the real hostname
  // after hydration so commands and links work when the operator reaches
  // the box by IP or a custom hostname instead of rasputin.local.
  const [host, setHost] = useState('rasputin.local');
  useEffect(() => {
    if (window.location.hostname) setHost(window.location.hostname);
  }, []);

  const caURL = `http://${host}/mesh-ca.pem`;
  const secureHome = `https://${host}/login`;

  const macCmd = `curl -fsS ${caURL} -o rasputin-mesh-ca.pem && sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rasputin-mesh-ca.pem`;
  const debianCmd = `curl -fsS ${caURL} -o rasputin-mesh-ca.crt && sudo cp rasputin-mesh-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`;
  const fedoraCmd = `curl -fsS ${caURL} -o rasputin-mesh-ca.pem && sudo cp rasputin-mesh-ca.pem /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust`;

  return (
    <div
      style={{
        minHeight: '100vh',
        background: '#07101f',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: MONO,
        padding: 24,
      }}
    >
      <div
        style={{
          width: 640,
          maxWidth: '100%',
          background: PANEL,
          border: `1px solid ${HAIR}`,
          padding: '28px 26px',
          display: 'flex',
          flexDirection: 'column',
          gap: 18,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldCheck size={14} color={ACCENT} />
          <span style={{ color: FG, fontSize: 13, letterSpacing: '0.18em' }}>RASPUTIN</span>
          <span style={{ marginLeft: 'auto', color: DIM, fontSize: 9, letterSpacing: '0.12em' }}>FIRST-RUN TRUST</span>
        </div>

        <div>
          <h1 style={{ color: FG, fontSize: 14, letterSpacing: '0.14em', margin: 0, fontWeight: 500 }}>
            SECURE YOUR CONNECTION
          </h1>
          <p style={{ color: DIM, fontSize: 11, lineHeight: 1.7, margin: '10px 0 0' }}>
            This system created its own certificate when it first powered on. Install it once on each
            device you&apos;ll use — after that, every connection to this system is a real, fully encrypted
            secure connection, with no browser warnings.
          </p>
        </div>

        <section>
          <SectionLabel>IPHONE / IPAD</SectionLabel>
          <LinkBtn href="/api/mesh/ios-profile" download>
            <Download size={11} /> DOWNLOAD CONFIGURATION PROFILE
          </LinkBtn>
          <Hint style={{ marginTop: 8 }}>
            After downloading, install it via Settings → General → VPN &amp; Device Management, then
            enable full trust under Settings → General → About → Certificate Trust Settings.
          </Hint>
        </section>

        <section>
          <SectionLabel>MACOS</SectionLabel>
          <Hint style={{ marginBottom: 6 }}>Run in Terminal (asks for your password):</Hint>
          <CmdBlock value={macCmd} />
        </section>

        <section>
          <SectionLabel>LINUX</SectionLabel>
          <Hint style={{ marginBottom: 6 }}>Debian / Ubuntu:</Hint>
          <CmdBlock value={debianCmd} />
          <Hint style={{ margin: '10px 0 6px' }}>Fedora / RHEL:</Hint>
          <CmdBlock value={fedoraCmd} />
        </section>

        <section>
          <SectionLabel>WINDOWS</SectionLabel>
          <LinkBtn href="/mesh-ca.pem" download>
            <Download size={11} /> DOWNLOAD CERTIFICATE
          </LinkBtn>
          <Hint style={{ marginTop: 8 }}>
            Open the downloaded file → Install Certificate… → Local Machine → Place all certificates in
            the following store → Trusted Root Certification Authorities.
          </Hint>
        </section>

        <div style={{ borderTop: `1px solid ${HAIR}`, paddingTop: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Firefox (and some other browsers) only read newly installed
              certificates from the system store at launch — found on the
              first Mu hardware bench, 2026-06-12. */}
          <Hint>
            Still seeing a warning after installing? Quit and reopen your browser — some browsers
            (Firefox in particular) only pick up new certificates when they start.
          </Hint>
          <LinkBtn href={secureHome} primary>
            CONTINUE SECURELY <ArrowRight size={12} />
          </LinkBtn>
          <Hint>
            In a hurry? You can <a href={secureHome} style={{ color: DIM }}>continue without installing
            the certificate</a> and accept your browser&apos;s warning — the connection is still encrypted,
            your browser just can&apos;t vouch for it yet.
          </Hint>
        </div>
      </div>
    </div>
  );
}

// Anchor styled like the kit's Btn — the kit component renders a <button>,
// and these actions are real navigations/downloads, so they stay <a>.
function LinkBtn({
  href,
  primary = false,
  download = false,
  children,
}: {
  href: string;
  primary?: boolean;
  download?: boolean;
  children: ReactNode;
}) {
  const [hover, setHover] = useState(false);
  const style: CSSProperties = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 6,
    padding: primary ? '8px 14px' : '6px 12px',
    border: `1px solid ${primary ? accentA(0.35) : 'rgba(228,230,234,0.22)'}`,
    background: hover
      ? primary
        ? accentA(0.16)
        : 'rgba(228,230,234,0.1)'
      : primary
        ? accentA(0.08)
        : 'rgba(228,230,234,0.04)',
    color: primary ? ACCENT : FG,
    fontSize: 10,
    fontFamily: MONO,
    letterSpacing: '0.08em',
    textDecoration: 'none',
    cursor: 'pointer',
    transition: 'background 0.15s',
    whiteSpace: 'nowrap',
    alignSelf: 'flex-start',
  };
  return (
    <a
      href={href}
      style={style}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      {...(download ? { download: true } : {})}
    >
      {children}
    </a>
  );
}

// Command + COPY overlay — same idiom as the mesh keys page's CopyBlock:
// every copyable value ships with a CopyButton, never a bare code block.
function CmdBlock({ value }: { value: string }) {
  return (
    <div style={{ position: 'relative' }}>
      <pre
        style={{
          margin: 0,
          padding: '8px 64px 8px 10px',
          background: '#060c16',
          border: `1px solid ${HAIR}`,
          color: '#cdd6e4',
          fontSize: 10,
          fontFamily: MONO,
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-all',
          lineHeight: 1.6,
        }}
      >
        {value}
      </pre>
      <div style={{ position: 'absolute', top: 4, right: 4 }}>
        <CopyButton value={value} />
      </div>
    </div>
  );
}
