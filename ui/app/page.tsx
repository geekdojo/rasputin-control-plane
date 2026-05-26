'use client';

import { Fragment, useEffect, useState } from 'react';
import {
  createJob,
  listEvents,
  listJobs,
  listNodes,
  listSteps,
  openInventoryWS,
  openJobsWS,
} from '../lib/api';
import type {
  InventoryChangeEvent,
  Job,
  JobEvent,
  JobStep,
  Node,
} from '../lib/types';

export default function HomePage() {
  return (
    <main>
      <header>
        <h1>Rasputin</h1>
        <p className="sub">Control plane · local dev</p>
      </header>
      <NodesSection />
      <TasksSection />
    </main>
  );
}

// ----- Nodes ---------------------------------------------------------------

function NodesSection() {
  const [nodes, setNodes] = useState<Node[]>([]);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    listNodes().then(setNodes).catch(console.error);
    const close = openInventoryWS((ev) => {
      setNodes((prev) => applyInventoryEvent(prev, ev));
    });
    return close;
  }, []);

  // Tick the "last seen" relative timestamps every second.
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <section className="nodes-section">
      <h2>Nodes</h2>
      {nodes.length === 0 ? (
        <p className="hint">
          no nodes registered yet — start <code>rasputin-agent</code> and one
          should appear here within a second
        </p>
      ) : (
        <div className="nodes-grid">
          {nodes.map((n) => (
            <NodeCard key={n.id} node={n} now={now} />
          ))}
        </div>
      )}
    </section>
  );
}

function NodeCard({ node, now }: { node: Node; now: number }) {
  const lastSeenMs = now - new Date(node.lastSeen).getTime();
  return (
    <article className={`node-card status-${node.status}`}>
      <header>
        <span className={`status status-${node.status}`}>{node.status}</span>
        <span className="role">{node.role}</span>
      </header>
      <h3>{node.id}</h3>
      <dl>
        <dt>host</dt>
        <dd>{node.hostname || <em>unknown</em>}</dd>
        <dt>last seen</dt>
        <dd>{relativeTime(lastSeenMs)}</dd>
        <dt>agent</dt>
        <dd>
          <code>{node.agentVersion}</code>
        </dd>
      </dl>
    </article>
  );
}

function applyInventoryEvent(prev: Node[], ev: InventoryChangeEvent): Node[] {
  const exists = prev.find((n) => n.id === ev.node.id);
  if (!exists) return [...prev, ev.node];
  return prev.map((n) => (n.id === ev.node.id ? ev.node : n));
}

function relativeTime(ms: number): string {
  if (ms < 0) return 'just now';
  if (ms < 1000) return 'just now';
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  return `${Math.floor(ms / 3_600_000)}h ago`;
}

// ----- Tasks ---------------------------------------------------------------

function TasksSection() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [steps, setSteps] = useState<JobStep[]>([]);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [nodeId, setNodeId] = useState('node-dev');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    listJobs()
      .then((js) => active && setJobs(js))
      .catch((e) => active && setErr(String(e)));

    const close = openJobsWS((ev) => {
      setJobs((prev) => applyJobEvent(prev, ev));
      if (ev.jobId === expanded) {
        refreshDetail(ev.jobId);
      }
    });
    return () => {
      active = false;
      close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!expanded) {
      setSteps([]);
      setEvents([]);
      return;
    }
    refreshDetail(expanded);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expanded]);

  function refreshDetail(id: string) {
    listSteps(id).then(setSteps).catch(console.error);
    listEvents(id).then(setEvents).catch(console.error);
  }

  async function handlePing() {
    setBusy(true);
    setErr(null);
    try {
      await createJob('diag.ping', { nodeId });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="tasks-section">
      <h2>Tasks</h2>
      <p className="hint">
        Every state-changing operation is a Job. Click a row for steps and events.
      </p>

      <div className="actions">
        <label>
          Node id&nbsp;
          <input
            value={nodeId}
            onChange={(e) => setNodeId(e.target.value)}
            placeholder="node-dev"
          />
        </label>
        <button onClick={handlePing} disabled={busy || !nodeId}>
          {busy ? 'sending…' : 'Ping node'}
        </button>
        {err && <span className="err">{err}</span>}
      </div>

      <table>
        <thead>
          <tr>
            <th>Job</th>
            <th>Kind</th>
            <th>Status</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          {jobs.length === 0 && (
            <tr>
              <td colSpan={4} className="empty">
                no jobs yet — click <em>Ping node</em> above
              </td>
            </tr>
          )}
          {jobs.map((j) => (
            <Fragment key={j.id}>
              <tr
                className="row"
                onClick={() => setExpanded(expanded === j.id ? null : j.id)}
              >
                <td>
                  <code>{j.id.slice(0, 8)}…</code>
                </td>
                <td>{j.kind}</td>
                <td>
                  <span className={`status status-${j.status}`}>{j.status}</span>
                </td>
                <td>{new Date(j.createdAt).toLocaleTimeString()}</td>
              </tr>
              {expanded === j.id && (
                <tr className="detail-row">
                  <td colSpan={4}>
                    <Detail job={j} steps={steps} events={events} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function Detail({
  job,
  steps,
  events,
}: {
  job: Job;
  steps: JobStep[];
  events: JobEvent[];
}) {
  return (
    <div className="detail">
      {job.error && <pre className="err">{job.error}</pre>}

      <h3>Steps</h3>
      {steps.length === 0 ? (
        <p className="hint">no steps recorded yet</p>
      ) : (
        <ul className="steps">
          {steps.map((s) => (
            <li key={s.seq}>
              <span className={`status status-${s.status}`}>{s.status}</span>
              <strong>{s.name}</strong>
              {s.attempt > 0 && (
                <span className="hint"> (attempt {s.attempt + 1})</span>
              )}
              {s.error && <pre className="err">{s.error}</pre>}
              {s.result !== undefined && s.result !== null && (
                <pre className="result">{pretty(s.result)}</pre>
              )}
            </li>
          ))}
        </ul>
      )}

      <h3>Events</h3>
      <ol className="events">
        {events.map((ev, i) => (
          <li key={ev.id ?? `${ev.ts}-${i}`}>
            <time>{new Date(ev.ts).toLocaleTimeString()}</time>
            <span className="ev-type">{ev.type}</span>
            {ev.data !== undefined && ev.data !== null && (
              <code>{summarize(ev.data)}</code>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}

function applyJobEvent(prev: Job[], ev: JobEvent): Job[] {
  if (ev.type === 'created') {
    const j = ev.data as Job | undefined;
    if (!j) return prev;
    if (prev.find((p) => p.id === j.id)) return prev;
    return [j, ...prev];
  }
  return prev.map((j) => {
    if (j.id !== ev.jobId) return j;
    switch (ev.type) {
      case 'started':
        return { ...j, status: 'running', startedAt: ev.ts };
      case 'succeeded':
        return { ...j, status: 'succeeded', finishedAt: ev.ts };
      case 'failed':
        return {
          ...j,
          status: 'failed',
          finishedAt: ev.ts,
          error: (ev.data as { error?: string } | undefined)?.error,
        };
      default:
        return j;
    }
  });
}

function pretty(v: unknown): string {
  try {
    return JSON.stringify(v, null, 2);
  } catch {
    return String(v);
  }
}

function summarize(v: unknown): string {
  const s = typeof v === 'string' ? v : JSON.stringify(v);
  return s.length > 120 ? s.slice(0, 117) + '…' : s;
}
