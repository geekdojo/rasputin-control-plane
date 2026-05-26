'use client';

import { Fragment, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  applyFirewall,
  createApp,
  createIntent,
  createJob,
  deleteApp,
  deleteIntent,
  deployApp,
  getMetrics,
  listApps,
  listEvents,
  listFirewallState,
  listIntents,
  listJobs,
  listNodes,
  listSteps,
  openAppsWS,
  openFirewallWS,
  openInventoryWS,
  openJobsWS,
  reconcileFirewall,
  stopApp,
} from '../lib/api';
import { getMe, logout, type CurrentUser } from '../lib/auth';
import type {
  App,
  FirewallIntent,
  FirewallNodeState,
  InventoryChangeEvent,
  Job,
  JobEvent,
  JobStep,
  MetricSeries,
  Node,
  PortForwardProto,
} from '../lib/types';

export default function HomePage() {
  const router = useRouter();
  const [user, setUser] = useState<CurrentUser | null | undefined>(undefined);

  useEffect(() => {
    getMe()
      .then((u) => {
        if (u === null) {
          router.replace('/login');
        } else {
          setUser(u);
        }
      })
      .catch(() => router.replace('/login'));
  }, [router]);

  async function handleLogout() {
    await logout();
    router.replace('/login');
  }

  if (user === undefined || user === null) {
    return (
      <main>
        <p className="hint">Loading…</p>
      </main>
    );
  }

  return (
    <main>
      <header className="with-user">
        <div>
          <h1>Rasputin</h1>
          <p className="sub">Control plane · local dev</p>
        </div>
        <div className="user-pill">
          <span>
            signed in as <strong>{user.displayName}</strong>
          </span>
          <button type="button" onClick={handleLogout}>
            sign out
          </button>
        </div>
      </header>
      <NodesSection />
      <AppsSection />
      <FirewallSection />
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
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [metrics, setMetrics] = useState<MetricSeries | null>(null);

  // Poll the api every 30s for this node's metrics. Light pressure since
  // each sample is just a few hundred bytes and the api reads are indexed.
  useEffect(() => {
    let active = true;
    const fetch = () => {
      getMetrics(node.id, '15m', [
        'cpu_percent',
        'mem_used_bytes',
        'mem_total_bytes',
      ])
        .then((m) => {
          if (active) setMetrics(m);
        })
        .catch(() => {
          /* swallow — sparkline just stays empty */
        });
    };
    fetch();
    const t = setInterval(fetch, 30_000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [node.id]);

  async function handleReboot() {
    setBusy(true);
    setErr(null);
    try {
      await createJob('node.reboot', { nodeId: node.id });
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  const cpuPoints = metrics?.series?.cpu_percent ?? [];
  const memUsedPoints = metrics?.series?.mem_used_bytes ?? [];
  const memTotalPoints = metrics?.series?.mem_total_bytes ?? [];
  const memPctValues = memUsedPoints.map((p, i) => {
    const total = memTotalPoints[i]?.value ?? 0;
    return total > 0 ? (p.value / total) * 100 : 0;
  });
  const cpuValues = cpuPoints.map((p) => p.value);
  const latestCpu = cpuValues.length ? cpuValues[cpuValues.length - 1] : null;
  const latestMem = memPctValues.length ? memPctValues[memPctValues.length - 1] : null;

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
      <div className="card-metrics">
        <MetricRow label="cpu" data={cpuValues} latest={latestCpu} color="var(--warn)" />
        <MetricRow label="mem" data={memPctValues} latest={latestMem} color="var(--accent)" />
      </div>
      <div className="card-actions">
        <button
          onClick={handleReboot}
          disabled={busy || node.status !== 'online'}
          title={node.status !== 'online' ? 'Node is not online' : 'Reboot this node'}
        >
          {busy ? 'sending…' : 'Reboot'}
        </button>
        {err && <span className="err">{err}</span>}
      </div>
    </article>
  );
}

function MetricRow({
  label,
  data,
  latest,
  color,
}: {
  label: string;
  data: number[];
  latest: number | null;
  color: string;
}) {
  return (
    <div className="metric-row">
      <span className="metric-label">{label}</span>
      <Sparkline data={data} max={100} color={color} />
      <span className="metric-value">
        {latest != null ? `${latest.toFixed(0)}%` : '—'}
      </span>
    </div>
  );
}

function Sparkline({
  data,
  max,
  color,
}: {
  data: number[];
  max: number;
  color: string;
}) {
  const w = 80;
  const h = 18;
  if (data.length < 2) {
    return <svg width={w} height={h} className="sparkline" aria-hidden />;
  }
  const safeMax = max > 0 ? max : 1;
  const xStep = w / (data.length - 1);
  const points = data
    .map((v, i) => {
      const x = (i * xStep).toFixed(1);
      const y = (h - (Math.min(Math.max(v, 0), safeMax) / safeMax) * h).toFixed(1);
      return `${x},${y}`;
    })
    .join(' ');
  return (
    <svg width={w} height={h} viewBox={`0 0 ${w} ${h}`} className="sparkline" aria-hidden>
      <polyline fill="none" stroke={color} strokeWidth={1.5} points={points} />
    </svg>
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

// ----- Apps ----------------------------------------------------------------

function AppsSection() {
  const [apps, setApps] = useState<App[]>([]);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [busy, setBusy] = useState<string | null>(null); // appId being mutated
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const closeApps = openAppsWS(() => {
      listApps().then(setApps).catch(console.error);
    });
    const closeInv = openInventoryWS(() => {
      listNodes().then(setNodes).catch(console.error);
    });
    return () => {
      closeApps();
      closeInv();
    };
  }, []);

  function refresh() {
    listApps().then(setApps).catch((e) => setErr(String(e)));
    listNodes().then(setNodes).catch(console.error);
  }

  async function handle(action: 'deploy' | 'stop' | 'delete', app: App) {
    setBusy(app.id);
    setErr(null);
    try {
      if (action === 'deploy') await deployApp(app.id);
      else if (action === 'stop') await stopApp(app.id);
      else {
        if (!confirm(`Delete app "${app.name}"? This removes the record; stop it first if it's running.`)) {
          return;
        }
        await deleteApp(app.id);
        setApps((prev) => prev.filter((a) => a.id !== app.id));
      }
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  const deployTargets = nodes.filter(
    (n) => n.role === 'compute' || n.role === 'controlplane',
  );

  return (
    <section className="apps-section">
      <h2>Apps</h2>
      {err && <pre className="err">{err}</pre>}

      {apps.length === 0 ? (
        <p className="hint">no apps yet — define one below</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Target</th>
              <th>Status</th>
              <th>Last deployed</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {apps.map((a) => (
              <tr key={a.id}>
                <td><strong>{a.name}</strong></td>
                <td><code>{a.targetNode}</code></td>
                <td>
                  <span className={`status status-${appStatusClass(a.lastStatus)}`}>
                    {a.lastStatus}
                  </span>
                  {a.lastDetail && (
                    <span className="hint" title={a.lastDetail}>
                      {' '}· {a.lastDetail.length > 40 ? a.lastDetail.slice(0, 37) + '…' : a.lastDetail}
                    </span>
                  )}
                </td>
                <td>{a.lastDeployed ? new Date(a.lastDeployed).toLocaleTimeString() : '—'}</td>
                <td className="row-actions">
                  {a.lastStatus !== 'running' && (
                    <button
                      onClick={() => handle('deploy', a)}
                      disabled={busy === a.id}
                    >
                      deploy
                    </button>
                  )}
                  {(a.lastStatus === 'running' || a.lastStatus === 'deploying' || a.lastStatus === 'failed') && (
                    <button
                      onClick={() => handle('stop', a)}
                      disabled={busy === a.id}
                    >
                      stop
                    </button>
                  )}
                  <button
                    onClick={() => handle('delete', a)}
                    disabled={busy === a.id}
                  >
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <AddAppForm
        deployTargets={deployTargets}
        onCreated={(a) => setApps((prev) => [...prev, a])}
      />
    </section>
  );
}

function appStatusClass(s: App['lastStatus']): string {
  switch (s) {
    case 'running': return 'succeeded';
    case 'failed': return 'failed';
    case 'deploying':
    case 'stopping': return 'running';
    case 'stopped': return 'queued';
    default: return 'pending';
  }
}

function AddAppForm({
  deployTargets,
  onCreated,
}: {
  deployTargets: Node[];
  onCreated: (a: App) => void;
}) {
  const [name, setName] = useState('');
  const [targetNode, setTargetNode] = useState('');
  const [composeYaml, setComposeYaml] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Default target to the first compute/controlplane node when one appears.
  useEffect(() => {
    if (!targetNode && deployTargets.length > 0) {
      setTargetNode(deployTargets[0].id);
    }
  }, [deployTargets, targetNode]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const created = await createApp({ name, targetNode, composeYaml });
      onCreated(created);
      setName('');
      setComposeYaml('');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (deployTargets.length === 0) {
    return (
      <div className="add-intent">
        <h4>Add app</h4>
        <p className="hint">no compute or controlplane nodes registered yet — start one to add apps</p>
      </div>
    );
  }

  return (
    <form className="add-intent add-app" onSubmit={submit}>
      <h4>Add app</h4>
      <div className="row">
        <input
          placeholder="name (e.g. nextcloud)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <select
          value={targetNode}
          onChange={(e) => setTargetNode(e.target.value)}
        >
          {deployTargets.map((n) => (
            <option key={n.id} value={n.id}>
              {n.id} ({n.role})
            </option>
          ))}
        </select>
      </div>
      <textarea
        placeholder={`services:\n  web:\n    image: nginx:alpine\n    ports:\n      - "8080:80"`}
        value={composeYaml}
        onChange={(e) => setComposeYaml(e.target.value)}
        required
        rows={8}
      />
      <div className="form-actions">
        <button type="submit" disabled={busy || !name || !targetNode || !composeYaml}>
          {busy ? 'adding…' : 'add'}
        </button>
        {err && <pre className="err">{err}</pre>}
      </div>
    </form>
  );
}

// ----- Firewall ------------------------------------------------------------

function FirewallSection() {
  const [intents, setIntents] = useState<FirewallIntent[]>([]);
  const [states, setStates] = useState<FirewallNodeState[]>([]);
  const [busy, setBusy] = useState<'apply' | 'reconcile' | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    refresh();
    const close = openFirewallWS(() => {
      // Any change event triggers a state refresh — small surface, cheap.
      listFirewallState().then(setStates).catch(console.error);
    });
    return close;
  }, []);

  function refresh() {
    listIntents().then(setIntents).catch((e) => setErr(String(e)));
    listFirewallState().then(setStates).catch(console.error);
  }

  async function handleApply() {
    setBusy('apply');
    setErr(null);
    try {
      await applyFirewall();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleReconcile() {
    setBusy('reconcile');
    setErr(null);
    try {
      await reconcileFirewall();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm('Delete this intent? It will remain on the firewall until you Apply again.')) return;
    try {
      await deleteIntent(id);
      setIntents((prev) => prev.filter((p) => p.id !== id));
    } catch (e) {
      setErr(String(e));
    }
  }

  return (
    <section className="firewall-section">
      <h2>Firewall</h2>

      {states.length === 0 ? (
        <p className="hint">
          No firewall-role agent is registered. Start one with{' '}
          <code>RASPUTIN_NODE_ROLE=firewall</code>.
        </p>
      ) : (
        <div className="firewall-state-bar">
          {states.map((s) => (
            <FirewallStateBadge key={s.nodeId} state={s} />
          ))}
          <div className="spacer" />
          <button onClick={handleApply} disabled={busy !== null}>
            {busy === 'apply' ? 'applying…' : 'Apply'}
          </button>
          <button onClick={handleReconcile} disabled={busy !== null}>
            {busy === 'reconcile' ? 'reconciling…' : 'Reconcile'}
          </button>
        </div>
      )}

      {err && <pre className="err">{err}</pre>}

      <h3>Port forwards</h3>
      {intents.length === 0 ? (
        <p className="hint">no intents yet</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>WAN port</th>
              <th>→</th>
              <th>LAN target</th>
              <th>Proto</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {intents.map((i) => (
              <tr key={i.id}>
                <td>
                  <strong>{i.name}</strong>
                  {!i.enabled && <span className="hint"> (disabled)</span>}
                </td>
                <td><code>{i.spec.wanPort}</code></td>
                <td className="arrow">→</td>
                <td><code>{i.spec.lanHost}:{i.spec.lanPort}</code></td>
                <td><code>{i.spec.protocol}</code></td>
                <td className="row-actions">
                  <button onClick={() => handleDelete(i.id)} title="Delete">
                    delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <AddPortForwardForm onCreated={(i) => setIntents((p) => [...p, i])} />
    </section>
  );
}

function FirewallStateBadge({ state }: { state: FirewallNodeState }) {
  const status: 'in-sync' | 'drift' | 'unknown' = state.drift
    ? 'drift'
    : state.lastApplied
    ? 'in-sync'
    : 'unknown';
  return (
    <div className={`fw-state fw-${status}`}>
      <span className="fw-state-label">{state.nodeId}</span>
      <span className="fw-state-pill">{status === 'in-sync' ? 'in sync' : status}</span>
      <span className="fw-state-meta">
        {state.lastApplied
          ? `applied ${new Date(state.lastApplied).toLocaleTimeString()}`
          : 'never applied'}
      </span>
    </div>
  );
}

function AddPortForwardForm({
  onCreated,
}: {
  onCreated: (i: FirewallIntent) => void;
}) {
  const [name, setName] = useState('');
  const [wanPort, setWanPort] = useState('');
  const [lanHost, setLanHost] = useState('');
  const [lanPort, setLanPort] = useState('');
  const [protocol, setProtocol] = useState<PortForwardProto>('tcp');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const created = await createIntent({
        kind: 'port_forward',
        name,
        enabled: true,
        spec: {
          wanPort: Number(wanPort),
          lanHost,
          lanPort: Number(lanPort),
          protocol,
        },
      });
      onCreated(created);
      setName('');
      setWanPort('');
      setLanHost('');
      setLanPort('');
      setProtocol('tcp');
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="add-intent" onSubmit={submit}>
      <h4>Add port forward</h4>
      <div className="row">
        <input
          placeholder="name (e.g. minecraft)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <input
          placeholder="WAN port"
          value={wanPort}
          onChange={(e) => setWanPort(e.target.value)}
          inputMode="numeric"
          required
        />
        <span className="arrow">→</span>
        <input
          placeholder="LAN host (10.0.0.50)"
          value={lanHost}
          onChange={(e) => setLanHost(e.target.value)}
          required
        />
        <input
          placeholder="LAN port"
          value={lanPort}
          onChange={(e) => setLanPort(e.target.value)}
          inputMode="numeric"
          required
        />
        <select
          value={protocol}
          onChange={(e) => setProtocol(e.target.value as PortForwardProto)}
        >
          <option value="tcp">tcp</option>
          <option value="udp">udp</option>
          <option value="tcpudp">tcp+udp</option>
        </select>
        <button type="submit" disabled={busy || !name || !wanPort || !lanHost || !lanPort}>
          {busy ? 'adding…' : 'add'}
        </button>
      </div>
      {err && <pre className="err">{err}</pre>}
    </form>
  );
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
