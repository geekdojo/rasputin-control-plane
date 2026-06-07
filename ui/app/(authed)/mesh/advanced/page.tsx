'use client';

import { ExternalLink } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getMeshState } from '../../../../lib/api';
import type { MeshStateEnvelope } from '../../../../lib/types';
import { Btn, Hint, SectionLabel, Tok } from '../../../../components/kit';

// Headplane covers anything Rasputin doesn't model on the mesh side: HuJSON
// ACLs, DNS overrides, exit-node selection, DERP map. Per locked decision
// #6 in mesh.md, it's a sibling tab — not embedded — to avoid cross-origin
// SSO friction.
export default function MeshAdvancedPage() {
  const [env, setEnv] = useState<MeshStateEnvelope | null>(null);

  useEffect(() => {
    getMeshState().then(setEnv).catch(() => {});
  }, []);

  return (
    <>
      <SectionLabel>HEADPLANE — Headscale admin UI</SectionLabel>
      <Hint style={{ marginBottom: 16 }}>
        Headplane is the upstream Headscale admin UI. Use it for anything Rasputin doesn&apos;t expose:{' '}
        <Tok>ACL HuJSON</Tok>, DNS overrides, exit-node selection, DERP map. It runs as a sibling tab —
        single sign-on shares the same session cookie.
      </Hint>

      {env?.headplaneUrl ? (
        <a
          href={env.headplaneUrl}
          target="_blank"
          rel="noopener noreferrer"
          style={{ textDecoration: 'none', display: 'inline-block', marginBottom: 24 }}
        >
          <Btn variant="primary" small>
            OPEN HEADPLANE <ExternalLink size={10} />
          </Btn>
        </a>
      ) : (
        <Hint style={{ marginBottom: 24 }}>
          Headplane isn&apos;t deployed on this controlplane. Set <Tok>RASPUTIN_HEADPLANE_URL</Tok> on the api
          to surface a link here.
        </Hint>
      )}

      <SectionLabel>WHAT HEADPLANE IS GOOD FOR</SectionLabel>
      <Hint>
        Rasputin owns the narrow intent surface — pre-auth keys, subnet routes, node enrollment —
        because those have stable user-facing concepts. Everything else passes through to Headplane.
        See <Tok>design/control-plane/mesh.md §3</Tok> for the split.
      </Hint>
    </>
  );
}
