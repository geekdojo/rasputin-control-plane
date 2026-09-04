'use client';

import { Ban, CheckCircle, Circle, ClipboardList, Loader, XCircle } from 'lucide-react';
import { Fragment, Suspense, useEffect, useRef, useState } from 'react';
import type { ElementType } from 'react';
import { useSearchParams } from 'next/navigation';
import { createJob, getJob, listApps, listEvents, listJobs, listSteps, openJobsWS } from '../../../lib/api';
import { focusNote, resolveFocus } from '../../../lib/task-focus';
import type { TaskFocus } from '../../../lib/task-focus';
import type { Job, JobEvent, JobStatus, JobStep, StepStatus } from '../../../lib/types';
import { Badge, Btn, DIM, FG, HAIR_SOFT, Input, LinkBtn, PageBody, PageHeader, PageShell, SectionLabel, tdStyle, thStyle } from '../../../components/kit';
import { ACCENT, accentA, MONO } from '../../../components/ui-theme';

const COLS = ['JOB', 'KIND', 'STATUS', 'NODE', 'STARTED', 'DURATION'];

function statusMeta(s: JobStatus): { color: string; icon: ElementType; spin?: boolean } {
  switch (s) {
    case 'running':
      return { color: ACCENT, icon: Loader, spin: true };
    case 'succeeded':
      return { color: '#4ade80', icon: CheckCircle };
    case 'failed':
      return { color: '#f87171', icon: XCircle };
    case 'cancelled':
      return { color: DIM, icon: Ban };
    default:
      return { color: DIM, icon: Circle }; // queued
  }
}

const STEP_COLOR: Record<StepStatus, string> = {
  pending: DIM,
  running: ACCENT,
  succeeded: '#4ade80',
  failed: '#f87171',
  compensated: '#facc15',
};

// Most sagas name their node in the spec. The app.* ones do not: they key on
// appId and the target node lives on the app record, so every install, stop and
// delete used to render NODE as an em dash — the operations most likely to be
// read here after something went wrong, and the column was blank for all of
// them. appNodes maps the gap.
function jobNode(j: Job, appNodes: Map<string, string>): string {
  if (j.spec && typeof j.spec === 'object' && 'nodeId' in j.spec) {
    const v = (j.spec as { nodeId?: unknown }).nodeId;
    if (typeof v === 'string' && v) return v;
  }
  const appId = jobApp(j);
  if (appId) {
    // Empty when the app has since been deleted — its jobs outlive it, and a
    // dash is honest there. Nothing else is recoverable.
    const node = appNodes.get(appId);
    if (node) return node;
  }
  return '—';
}

// The app.* sagas key their spec on appId, which is what lets an app's detail
// drawer link straight at the run that failed it (?app=<id>) instead of
// dropping the operator into an unfiltered queue.
function jobApp(j: Job): string | null {
  if (j.spec && typeof j.spec === 'object' && 'appId' in j.spec) {
    const v = (j.spec as { appId?: unknown }).appId;
    if (typeof v === 'string' && v) return v;
  }
  return null;
}

function fmtDuration(j: Job): string {
  if (!j.startedAt) return '—';
  if (!j.finishedAt) return 'running';
  const s = Math.max(0, Math.round((new Date(j.finishedAt).getTime() - new Date(j.startedAt).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function TasksInner() {
  const search = useSearchParams();
  const appFilter = search?.get('app') ?? null;
  // ?id=<jobId>: the job "Watch in Tasks" and the /alerts drill-through point
  // at. It is opened once per id (lib/task-focus.ts has the rules) and the
  // parameter stays in the URL so a refresh reopens it.
  const focusId = search?.get('id') ?? null;
  const [jobs, setJobs] = useState<Job[]>([]);
  // True once listJobs has answered, either way. The ?id= lookup waits for
  // it: deciding "not in the list" against an empty list that simply has not
  // arrived yet would fetch every focused job and mislabel it as outside.
  const [loaded, setLoaded] = useState(false);
  const [focus, setFocus] = useState<TaskFocus | null>(null);
  // The ?id= this page has already acted on. A ref, not state: it is a
  // guard read inside the effect, never rendered, and it is what stops a
  // job the operator has collapsed from popping open again on the next
  // render — the id is applied once per value, not once per render.
  const focusApplied = useRef<string | null>(null);
  // appId -> target node, so app.* jobs can fill the NODE column they have no
  // spec field for. See jobNode.
  const [appNodes, setAppNodes] = useState<Map<string, string>>(new Map());
  const [expanded, setExpanded] = useState<string | null>(null);
  // Mirror of `expanded` for the jobs WebSocket handler, which is installed
  // once on mount and would otherwise close over the initial null forever —
  // so an open detail never refreshed on a live event, which is the one
  // thing "watch" needs it to do.
  const expandedRef = useRef<string | null>(null);
  const [steps, setSteps] = useState<JobStep[]>([]);
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [nodeId, setNodeId] = useState('node-dev');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Declared before the effects that call it. It was a hoisted function
  // declaration below them, which works at runtime but reads as use-before-
  // declare to the React Compiler.
  function refreshDetail(id: string) {
    listSteps(id).then(setSteps).catch(() => {});
    listEvents(id).then(setEvents).catch(() => {});
  }

  useEffect(() => {
    let active = true;
    listJobs()
      .then((js) => {
        if (!active) return;
        setJobs(js);
        setLoaded(true);
      })
      .catch((e) => {
        if (!active) return;
        setErr(String(e));
        setLoaded(true);
      });
    // Best-effort: the NODE column degrades to a dash without this, so a
    // failure here is not worth surfacing over the jobs themselves.
    listApps()
      .then((as) => active && setAppNodes(new Map(as.map((a) => [a.id, a.targetNode]))))
      .catch(() => {});
    const close = openJobsWS((ev) => {
      setJobs((prev) => applyJobEvent(prev, ev));
      // A pinned job (outside the list) is not in `jobs`, so its status
      // would otherwise freeze at whatever the fetch returned.
      setFocus((f) =>
        f && f.state === 'outside' && ev.type !== 'created' && ev.jobId === f.job.id
          ? { ...f, job: applyJobEvent([f.job], ev)[0] ?? f.job }
          : f,
      );
      if (ev.jobId === expandedRef.current) refreshDetail(ev.jobId);
    });
    return () => {
      active = false;
      close();
    };
  }, []);

  // No clearing branch: the row already renders `expanded === j.id ? steps : []`,
  // so wiping state here was redundant with the guard below AND was a
  // synchronous setState inside an effect (react-hooks/set-state-in-effect).
  useEffect(() => {
    expandedRef.current = expanded;
    if (expanded) refreshDetail(expanded);
  }, [expanded]);

  // Open the job named by ?id=, once the list is in. Runs again whenever the
  // list changes (live events) but the guard makes every run after the first
  // for a given id a no-op — including after the operator collapses it.
  // Nothing is set synchronously here; the result lands from the promise.
  useEffect(() => {
    if (!focusId || !loaded || focusApplied.current === focusId) return;
    focusApplied.current = focusId;
    const visible = appFilter ? jobs.filter((j) => jobApp(j) === appFilter) : jobs;
    resolveFocus(focusId, jobs, visible, getJob).then((f) => {
      setFocus(f);
      if (f.state === 'listed' || f.state === 'outside') setExpanded(f.job.id);
    });
  }, [focusId, loaded, jobs, appFilter]);

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

  const shown = appFilter ? jobs.filter((j) => jobApp(j) === appFilter) : jobs;
  // The focused job sits above the table when the page would not otherwise
  // show it. Not when the list has since caught up with it (a live 'created'
  // event, say): one row per job.
  const pinned = focus?.state === 'outside' && !shown.some((j) => j.id === focus.job.id) ? focus.job : null;
  const focusedId = focus && (focus.state === 'listed' || focus.state === 'outside') ? focus.job.id : null;
  const note = focus ? focusNote(focus, appFilter) : null;
  const running = shown.filter((j) => j.status === 'running').length;
  const queued = shown.filter((j) => j.status === 'queued').length;
  const failed = shown.filter((j) => j.status === 'failed').length;

  return (
    <PageShell>
      <PageHeader
        icon={ClipboardList}
        title={`TASK QUEUE — ${running} RUNNING · ${queued} QUEUED · ${failed} FAILED`}
        right={
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Input
              value={nodeId}
              onChange={(e) => setNodeId(e.target.value)}
              placeholder="node-dev"
              style={{ width: 130, fontSize: 10, padding: '4px 8px' }}
            />
            <Btn variant="primary" small disabled={busy || !nodeId} onClick={handlePing}>
              {busy ? 'PINGING…' : 'PING NODE'}
            </Btn>
          </div>
        }
      />
      <PageBody>
        {err && <div style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}>{err}</div>}

        {appFilter && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>filtered to app {appFilter}</span>
            <LinkBtn href="/tasks" small>
              SHOW ALL
            </LinkBtn>
          </div>
        )}

        {note && (
          <div
            role="status"
            style={{ color: focus?.state === 'outside' ? DIM : '#facc15', fontSize: 10, fontFamily: MONO, marginBottom: 12 }}
          >
            {note}
          </div>
        )}

        <table aria-label="Task queue" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {COLS.map((c) => (
                <th key={c} scope="col" style={thStyle}>
                  {c}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pinned && (
              <JobRow
                key={pinned.id}
                job={pinned}
                node={jobNode(pinned, appNodes)}
                expanded={expanded === pinned.id}
                focused={focusedId === pinned.id}
                steps={expanded === pinned.id ? steps : []}
                events={expanded === pinned.id ? events : []}
                onToggle={() => setExpanded(expanded === pinned.id ? null : pinned.id)}
              />
            )}
            {shown.length === 0 && (
              <tr>
                <td colSpan={COLS.length} style={{ ...tdStyle, color: DIM, padding: '16px 0' }}>
                  {appFilter
                    ? 'no jobs recorded for this app yet'
                    : 'no jobs yet — operations from other sections will show up here'}
                </td>
              </tr>
            )}
            {shown.map((j) => (
              <JobRow
                key={j.id}
                job={j}
                node={jobNode(j, appNodes)}
                expanded={expanded === j.id}
                focused={focusedId === j.id}
                steps={expanded === j.id ? steps : []}
                events={expanded === j.id ? events : []}
                onToggle={() => setExpanded(expanded === j.id ? null : j.id)}
              />
            ))}
          </tbody>
        </table>
      </PageBody>
    </PageShell>
  );
}

// useSearchParams must sit under a Suspense boundary for the static export
// to prerender this route.
export default function TasksPage() {
  return (
    <Suspense fallback={null}>
      <TasksInner />
    </Suspense>
  );
}

function JobRow({
  job,
  node,
  expanded,
  focused,
  steps,
  events,
  onToggle,
}: {
  job: Job;
  node: string;
  expanded: boolean;
  // The row ?id= named: scrolled into view and flashed once when it becomes
  // focused. The flash is a one-shot CSS animation (globals.css task-flash)
  // rather than state with a timer, so it needs no cleanup and cannot
  // re-run when the row re-renders.
  focused: boolean;
  steps: JobStep[];
  events: JobEvent[];
  onToggle: () => void;
}) {
  const [hover, setHover] = useState(false);
  const rowRef = useRef<HTMLTableRowElement | null>(null);
  const meta = statusMeta(job.status);
  const Icon = meta.icon;

  useEffect(() => {
    if (focused) rowRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, [focused]);

  return (
    <Fragment>
      <tr
        ref={rowRef}
        onClick={onToggle}
        onMouseEnter={() => setHover(true)}
        onMouseLeave={() => setHover(false)}
        data-focused={focused || undefined}
        style={{
          cursor: 'pointer',
          background: expanded || hover ? accentA(0.06) : 'transparent',
          transition: 'background 0.1s',
          animation: focused ? 'task-flash 1.8s ease-out' : undefined,
        }}
      >
        <td style={{ ...tdStyle, color: DIM }}>{job.id.slice(0, 8)}…</td>
        <td style={{ ...tdStyle, color: FG }}>{job.kind}</td>
        <td style={tdStyle}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <Icon size={11} color={meta.color} style={meta.spin ? { animation: 'spin 1.2s linear infinite' } : undefined} />
            <span style={{ color: meta.color, letterSpacing: '0.06em' }}>{job.status.toUpperCase()}</span>
          </span>
        </td>
        <td style={{ ...tdStyle, color: DIM }}>{node}</td>
        <td style={{ ...tdStyle, color: DIM }}>{job.startedAt ? new Date(job.startedAt).toLocaleTimeString() : '—'}</td>
        <td style={{ ...tdStyle, color: DIM, paddingRight: 0 }}>{fmtDuration(job)}</td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={6} style={{ padding: '4px 0 16px' }}>
            <Detail job={job} steps={steps} events={events} />
          </td>
        </tr>
      )}
    </Fragment>
  );
}

function Detail({ job, steps, events }: { job: Job; steps: JobStep[]; events: JobEvent[] }) {
  return (
    <div style={{ borderLeft: `2px solid ${accentA(0.4)}`, paddingLeft: 14, marginLeft: 2, display: 'flex', flexDirection: 'column', gap: 14 }}>
      {job.error && (
        <pre style={{ color: '#f87171', fontSize: 10, fontFamily: MONO, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{job.error}</pre>
      )}

      <div>
        <SectionLabel>STEPS</SectionLabel>
        {steps.length === 0 ? (
          <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>no steps recorded yet</span>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {steps.map((s) => (
              <div key={s.seq} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Badge color={STEP_COLOR[s.status]}>{s.status.toUpperCase()}</Badge>
                  <span style={{ color: FG, fontSize: 10, fontFamily: MONO }}>{s.name}</span>
                  {s.attempt > 0 && <span style={{ color: DIM, fontSize: 9, fontFamily: MONO }}>(attempt {s.attempt + 1})</span>}
                </div>
                {s.error && <pre style={preStyle('#f87171')}>{s.error}</pre>}
                {s.result != null && <pre style={preStyle(DIM)}>{pretty(s.result)}</pre>}
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <SectionLabel>EVENTS</SectionLabel>
        {events.length === 0 ? (
          <span style={{ color: DIM, fontSize: 10, fontFamily: MONO }}>—</span>
        ) : (
          <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {events.map((ev, i) => (
              <li key={ev.id ?? `${ev.ts}-${i}`} style={{ display: 'flex', gap: 10, alignItems: 'baseline' }}>
                <time style={{ color: DIM, fontSize: 9, fontFamily: MONO, flexShrink: 0 }}>{new Date(ev.ts).toLocaleTimeString()}</time>
                <span style={{ color: ACCENT, fontSize: 9, fontFamily: MONO, letterSpacing: '0.06em', flexShrink: 0 }}>{ev.type}</span>
                {ev.data != null && <span style={{ color: DIM, fontSize: 9, fontFamily: MONO, wordBreak: 'break-word' }}>{summarize(ev.data)}</span>}
              </li>
            ))}
          </ol>
        )}
      </div>
    </div>
  );
}

function preStyle(color: string) {
  return {
    color,
    fontSize: 9,
    fontFamily: MONO,
    margin: '2px 0 0',
    padding: '6px 8px',
    background: 'rgba(var(--rasp-fg-rgb),0.03)',
    border: `1px solid ${HAIR_SOFT}`,
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-word' as const,
  };
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
        return { ...j, status: 'failed', finishedAt: ev.ts, error: (ev.data as { error?: string } | undefined)?.error };
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
