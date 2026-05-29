'use client';

import { ArrowLeft, Terminal } from 'lucide-react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { bmcSOLURL } from '../../../../lib/api';
import { Badge, Btn, DIM, HAIR, Input, PageHeader, PageShell } from '../../../../components/kit';
import { MONO } from '../../../../components/ui-theme';

type ConnState = 'connecting' | 'open' | 'closed' | 'error';

const CONN_COLOR: Record<ConnState, string> = {
  connecting: '#facc15',
  open: '#4ade80',
  closed: 'rgba(148,163,184,0.6)',
  error: '#f87171',
};

// SOL console (v0): a simple autoscrolling <pre>, line-oriented input. xterm.js
// + raw keypress capture is the v1 upgrade when wired to a real serial port.
export default function ConsolePage() {
  const params = useParams<{ nodeId: string }>();
  const nodeId = decodeURIComponent(params.nodeId);
  const [lines, setLines] = useState<string[]>([]);
  const [connected, setConnected] = useState<ConnState>('connecting');
  const [input, setInput] = useState('');
  const wsRef = useRef<WebSocket | null>(null);
  const paneRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
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
  }, [nodeId]);

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
          v0 mock backend emits a banner + uptime line every 2s and echoes typed input. Real BMC wiring lands with chassis hardware.
        </p>
      </div>
    </PageShell>
  );
}
