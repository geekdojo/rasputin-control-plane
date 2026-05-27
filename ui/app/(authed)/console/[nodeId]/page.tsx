'use client';

import { useEffect, useRef, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { bmcSOLURL } from '../../../../lib/api';

// SOL console page. v0 uses a simple `<pre>` with autoscroll — no xterm.js.
// Sufficient for mock-mode dev where output is line-oriented; we'll swap
// in xterm.js when we wire to a real serial port and need ANSI handling.
//
// Input mode: the page captures a small text-input field below the output
// pane. Each line submitted is sent over the WS as the bytes typed. Most
// SOL sessions on Linux nodes are character-oriented; line-oriented input
// is good enough for the operator to issue commands. xterm.js + raw-mode
// keypress capture is the v1 upgrade.
export default function ConsolePage() {
  const params = useParams<{ nodeId: string }>();
  const nodeId = decodeURIComponent(params.nodeId);
  const [lines, setLines] = useState<string[]>([]);
  const [connected, setConnected] = useState<'connecting' | 'open' | 'closed' | 'error'>('connecting');
  const [input, setInput] = useState('');
  const wsRef = useRef<WebSocket | null>(null);
  const paneRef = useRef<HTMLPreElement | null>(null);

  useEffect(() => {
    const url = bmcSOLURL(nodeId);
    const ws = new WebSocket(url);
    wsRef.current = ws;
    ws.onopen = () => setConnected('open');
    ws.onmessage = (ev) => {
      setLines((prev) => {
        const next = [...prev, typeof ev.data === 'string' ? ev.data : ''];
        // Cap retained scrollback so the DOM doesn't grow unbounded.
        if (next.length > 2000) return next.slice(next.length - 2000);
        return next;
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

  // Autoscroll on new output. Skipped if the user has scrolled up to read.
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
    <section className="console-section">
      <header className="console-header">
        <h2>
          Serial console · <code>{nodeId}</code>
        </h2>
        <span className={`status sol-${connected}`}>{connected}</span>
        <Link href="/" className="console-back">
          ← Nodes
        </Link>
      </header>
      <pre ref={paneRef} className="console-pane">
        {lines.join('')}
      </pre>
      <form className="console-input" onSubmit={sendLine}>
        <input
          autoFocus
          placeholder={
            connected === 'open'
              ? 'type a line and press Enter'
              : 'waiting for connection…'
          }
          value={input}
          disabled={connected !== 'open'}
          onChange={(e) => setInput(e.target.value)}
        />
        <button type="submit" disabled={connected !== 'open'}>
          send
        </button>
      </form>
      <p className="hint">
        v0 mock backend emits a banner + uptime line every 2 s and echoes
        typed input. Real BMC wiring lands with chassis hardware.
      </p>
    </section>
  );
}
