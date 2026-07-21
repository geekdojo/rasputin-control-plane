'use client';

import { ArrowLeft, Terminal } from 'lucide-react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { Suspense, useEffect, useRef, useState } from 'react';
import { bmcSOLURL, listNodes } from '../../../lib/api';
import { bmcReachableNodes } from '../../../lib/bmc';
import { Badge, Btn, DIM, HAIR, Input, PageHeader, PageShell } from '../../../components/kit';
import { MONO } from '../../../components/ui-theme';

type ConnState = 'connecting' | 'open' | 'closed' | 'error';

const CONN_COLOR: Record<ConnState, string> = {
  connecting: '#facc15',
  open: '#4ade80',
  closed: 'rgba(148,163,184,0.6)',
  error: '#f87171',
};

// SOL console (v0): a simple autoscrolling <pre>, line-oriented input. xterm.js
// + raw keypress capture is the v1 upgrade when wired to a real serial port.
//
// The node id rides in ?node= rather than a path segment: the UI ships as a
// Next static export (one .html per route baked at build time), and node ids
// only exist at runtime.
function ConsoleInner() {
  const search = useSearchParams();
  const nodeId = search.get('node') ?? '';
  const [lines, setLines] = useState<string[]>([]);
  const [connected, setConnected] = useState<ConnState>('connecting');
  const [input, setInput] = useState('');
  // Per-node gate (lib/bmc.ts): null = still checking, then whether some
  // BMC host advertises this node. The control that links here is already
  // gated, but the route is reachable by direct URL — check again. The
  // api enforces the same gate server-side (403 on the WS).
  const [reachable, setReachable] = useState<boolean | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const paneRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    if (!nodeId) return;
    let active = true;
    setReachable(null);
    listNodes()
      .then((ns) => {
        if (active) setReachable(bmcReachableNodes(ns).has(nodeId));
      })
      .catch(() => {
        if (active) setReachable(false);
      });
    return () => {
      active = false;
    };
  }, [nodeId]);

  useEffect(() => {
    if (!nodeId || reachable !== true) return;
    const ws = new WebSocket(bmcSOLURL(nodeId));
    wsRef.current = ws;
    ws.onopen = () => setConnected('open');
    ws.onmessage = (ev) => {
      setLines((prev) => {
        const next = [...prev, typeof ev.data === 'string' ? ev.data : ''];
        return next.length > 2000 ? next.slice(next.length - 2000) : next;
      });
    };
    ws.onerror = () => setConnected('error');
    ws.onclose = () => setConnected('closed');
    return () => {
      try {
        ws.close();
      } catch {
        /* ignore */
      }
    };
  }, [nodeId, reachable]);

  useEffect(() => {
    const el = paneRef.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [lines]);

  function sendLine(e: React.FormEvent) {
    e.preventDefault();
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(input + '\n');
    setInput('');
  }

  if (nodeId && reachable === false) {
    return (
      <PageShell>
        <PageHeader icon={Terminal} title="SERIAL CONSOLE" />
        <div style={{ padding: '14px 20px' }}>
          <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>
            No BMC host reaches this node&apos;s serial line — the console isn&apos;t available for it.{' '}
            <Link href="/" style={{ color: DIM }}>
              Back to nodes
            </Link>
          </p>
        </div>
      </PageShell>
    );
  }

  if (!nodeId) {
    return (
      <PageShell>
        <PageHeader icon={Terminal} title="SERIAL CONSOLE" />
        <div style={{ padding: '14px 20px' }}>
          <p style={{ color: DIM, fontSize: 11, fontFamily: MONO }}>
            No node selected. Open a console from a node&apos;s controls.{' '}
            <Link href="/" style={{ color: DIM }}>
              Back to nodes
            </Link>
          </p>
        </div>
      </PageShell>
    );
  }

  return (
    <PageShell>
      <PageHeader
        icon={Terminal}
        title={`SERIAL CONSOLE · ${nodeId.toUpperCase()}`}
        right={
          <>
            <Badge color={CONN_COLOR[connected]}>{connected.toUpperCase()}</Badge>
            <Link href="/" style={{ textDecoration: 'none' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, color: DIM, fontSize: 10, letterSpacing: '0.08em' }}>
                <ArrowLeft size={12} color={DIM} /> NODES
              </span>
            </Link>
          </>
        }
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', padding: '14px 20px', gap: 10 }}>
        <pre
          ref={paneRef}
          style={{
            flex: 1,
            margin: 0,
            overflowY: 'auto',
            background: '#060c16',
            border: `1px solid ${HAIR}`,
            color: '#cdd6e4',
            fontSize: 11,
            fontFamily: MONO,
            lineHeight: 1.55,
            padding: '12px 14px',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-word',
          }}
        >
          {lines.join('')}
        </pre>

        <form onSubmit={sendLine} style={{ display: 'flex', gap: 8 }}>
          <Input
            autoFocus
            value={input}
            disabled={connected !== 'open'}
            onChange={(e) => setInput(e.target.value)}
            placeholder={connected === 'open' ? 'type a line and press Enter' : 'waiting for connection…'}
            style={{ flex: 1 }}
          />
          <Btn type="submit" variant="primary" disabled={connected !== 'open'}>
            SEND
          </Btn>
        </form>

        <p style={{ color: DIM, fontSize: 10, fontFamily: MONO, margin: 0, opacity: 0.7 }}>
          Line-mode v0 console (Enter sends the line). xterm.js character-mode is the planned upgrade.
        </p>
      </div>
    </PageShell>
  );
}

// useSearchParams must sit under a Suspense boundary for the static export
// to prerender this route.
export default function ConsolePage() {
  return (
    <Suspense fallback={null}>
      <ConsoleInner />
    </Suspense>
  );
}
