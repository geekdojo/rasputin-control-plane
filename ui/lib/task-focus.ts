// Opening the task named by `/tasks?id=<jobId>` (geekdojo-brain#291).
//
// "Watch in Tasks" on the app-restore modal, and the job drill-through on
// /alerts, both land on /tasks?id=<jobId>. Until 2026-09-04 the page ignored
// the parameter and the operator had to find the eight-character prefix by
// eye in a queue of fifty. The rules for what the page does with the id live
// here, as pure functions, so they are tested without rendering anything
// (see tsconfig.test.json for why this frontend's tests look like this).
//
// Three outcomes, in the order they are tried:
//
//   listed  — the job is in the list the page already holds AND the current
//             filter shows it. Expand it in place; nothing is fetched.
//   outside — the job exists but the page would not show it: it is older
//             than the fifty most recent (listJobs' default limit) or an
//             ?app= filter hides it. It is fetched by id (or, when the list
//             holds it and only the filter hides it, taken from the list)
//             and pinned above the table with a note saying why.
//   missing — GET /api/jobs/{id} answered 404. The page says so inline and
//             the list is left exactly as it was.
//
// A fetch failure that is NOT a 404 is reported as `error`, not `missing`:
// "this task does not exist" and "the api is unreachable" are different
// facts and the operator should not be told the first when the second is
// true.

import { isNotFound } from './api';
import type { Job } from './types';

export type TaskFocus =
  | { state: 'listed'; job: Job }
  | { state: 'outside'; job: Job }
  | { state: 'missing'; id: string }
  | { state: 'error'; id: string; message: string };

/**
 * Where the focused job stands relative to what the page holds, decided
 * without touching the network. `shown` is the visible slice of `loaded`
 * (the ?app= filter applied); `loaded` is everything listJobs returned.
 *
 *   'listed'  → it is on screen; expand it there.
 *   'hidden'  → loaded but filtered out; no fetch needed, pin it.
 *   'unknown' → not loaded; ask the api.
 */
export function locateFocus(
  id: string,
  loaded: readonly Job[],
  shown: readonly Job[],
): { where: 'listed'; job: Job } | { where: 'hidden'; job: Job } | { where: 'unknown' } {
  const onScreen = shown.find((j) => j.id === id);
  if (onScreen) return { where: 'listed', job: onScreen };
  const held = loaded.find((j) => j.id === id);
  if (held) return { where: 'hidden', job: held };
  return { where: 'unknown' };
}

/**
 * Resolve `?id=` to what the page should render. `fetchJob` is
 * api.getJob, injected so the decision can be exercised without a server
 * and so the test can prove it is called exactly when it should be.
 */
export async function resolveFocus(
  id: string,
  loaded: readonly Job[],
  shown: readonly Job[],
  fetchJob: (id: string) => Promise<Job>,
): Promise<TaskFocus> {
  const at = locateFocus(id, loaded, shown);
  if (at.where === 'listed') return { state: 'listed', job: at.job };
  if (at.where === 'hidden') return { state: 'outside', job: at.job };
  try {
    return { state: 'outside', job: await fetchJob(id) };
  } catch (e) {
    if (isNotFound(e)) return { state: 'missing', id };
    return { state: 'error', id, message: e instanceof Error ? e.message : String(e) };
  }
}

/** The inline note for a focus that is not simply "expanded in place". */
export function focusNote(f: TaskFocus, appFilter: string | null): string | null {
  switch (f.state) {
    case 'listed':
      return null;
    case 'outside':
      return appFilter
        ? `task ${f.job.id} is outside the current filter (app ${appFilter}) — shown above the list`
        : `task ${f.job.id} is older than the list below — shown above it`;
    case 'missing':
      return `task ${f.id} not found`;
    case 'error':
      return `task ${f.id} could not be loaded: ${f.message}`;
  }
}
