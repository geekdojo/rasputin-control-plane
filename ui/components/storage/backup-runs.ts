// The decisions BackupRuns.tsx makes, extracted so they can be executed rather
// than asserted in a comment.
//
// `ui/`'s test runner compiles `lib/**/*.ts` and `components/storage/*.ts` and
// runs them under `node --test` — no rendering framework, deliberately (see
// tsconfig.test.json for why that trade was taken). So anything in a `.tsx`
// file is compiled and type-checked but never executed. The rule that follows:
// if a rendering decision MATTERS, it does not live in the component.
//
// The one here matters more than any other on the page. `shouldWarnIncomplete`
// decides whether an operator is told their backups contain no app data. Get it
// wrong in the safe direction and they see a caveat that will one day be stale;
// get it wrong in the other and they believe their password vault is on that
// disk when it is not.

import type { BackupScheduleRequest } from '../../lib/api';
import type { BackupRunsResponse, BackupSchedule } from '../../lib/types';

/**
 * Whether to show the "not a complete backup" banner.
 *
 * FAIL LOUD. Anything other than a positive, explicit `scope: "full"` warns:
 * `controlplane-local` and `identity-only` (what earlier builds wrote), a
 * response that has not arrived, an api that sends no scope at all, a value
 * this build does not recognise. The banner going away is a claim that the
 * generation reaches everything, and only the api saying so in those words
 * earns it — which, since the per-node transport, it does. Whether one RUN
 * captured everything is the row's `complete`, rendered per run.
 */
export function shouldWarnIncomplete(data: BackupRunsResponse | null): boolean {
  return data?.scope !== 'full';
}

/**
 * The banner's headline, from the api's scope rather than from a constant here.
 *
 * The api owns the scope string (proto.BackupScopeControlplaneLocal) and the
 * prose beneath it; this turns the one into a heading in the same words. A
 * hard-coded "IDENTITY ONLY" survived one scope change already by saying
 * something that was no longer true, which is the drift the single exported
 * string exists to prevent.
 */
export function scopeHeadline(data: BackupRunsResponse | null): string {
  const scope = data?.scope;
  if (!scope) return 'SCOPE UNKNOWN — NOT A COMPLETE BACKUP';
  return `${scope.toUpperCase()} — NOT A COMPLETE BACKUP`;
}

/**
 * The per-run scope tooltip: what went in and what did not, in one line.
 *
 * Both numbers, always. "2 app volumes captured" on its own reads as success on
 * a run that missed four.
 */
export function runScopeTitle(run: {
  appVolumesCaptured: number;
  appVolumesSkipped?: number;
  appVolumesFailed?: number;
  warning?: string;
}): string {
  const parts = [appVolumeSummary(run.appVolumesCaptured)];
  const skipped = run.appVolumesSkipped ?? 0;
  const failed = run.appVolumesFailed ?? 0;
  // FAILED first and in capitals: §4.4's "failed, not skipped" — a volume the
  // run tried to take and could not is the loudest thing on the row.
  if (failed > 0) parts.push(`${failed} FAILED`);
  if (skipped - failed > 0) parts.push(`${skipped - failed} NOT captured`);
  if (run.warning) parts.push(run.warning);
  return parts.join(' · ');
}

/** The `off` sentinel the cadence select uses for a disabled schedule. */
export const CADENCE_OFF = 'off';

/**
 * The cadence select's current value.
 *
 * A disabled schedule renders as the explicit `off` option rather than as a
 * blank or a greyed control: §4.4's posture is that the absence of backups must
 * never look like ordinary green, and an operator has to be able to SEE that
 * nothing is scheduled.
 */
export function cadenceValue(schedule: BackupSchedule | null): string {
  if (!schedule) return CADENCE_OFF;
  if (!schedule.enabled) return CADENCE_OFF;
  return schedule.every ?? schedule.defaultEvery;
}

/**
 * The PUT body for a cadence the operator picked.
 *
 * Carries the CURRENT retention depth along, because the api's PUT is the
 * whole setting and a body without `retain` would silently reset the depth to
 * the default — a cadence change must not be able to change how many
 * generations are kept.
 */
export function cadenceRequest(value: string, current?: BackupSchedule | null): BackupScheduleRequest {
  const retain = current?.retain;
  if (value === CADENCE_OFF) return retain ? { enabled: false, retain } : { enabled: false };
  return retain ? { enabled: true, every: value, retain } : { enabled: true, every: value };
}

/**
 * The retention depths the "Generations kept" control offers, inside the api's
 * bounds (1..52). A curated list rather than every integer: the choice is
 * "how much history", and these are the sizes that mean something at a weekly
 * cadence — a month (the default), a quarter, a year.
 */
export const RETAIN_OPTIONS: number[] = [1, 2, 3, 4, 6, 8, 12, 26, 52];

/**
 * The options the retention select renders: the curated list, with the
 * current value inserted if it is not one of them — a depth set through the
 * api to a number the list does not carry must still render as itself, not
 * as the nearest option.
 */
export function retainOptions(schedule: BackupSchedule | null): number[] {
  const current = retainValue(schedule);
  if (RETAIN_OPTIONS.includes(current)) return RETAIN_OPTIONS;
  return [...RETAIN_OPTIONS, current].sort((a, b) => a - b);
}

/** The retention select's current value: the api's resolved depth, or its default. */
export function retainValue(schedule: BackupSchedule | null): number {
  if (!schedule) return 4;
  if (schedule.retain >= 1) return schedule.retain;
  return schedule.defaultRetain >= 1 ? schedule.defaultRetain : 4;
}

/**
 * The PUT body for a retention depth the operator picked. Carries the current
 * cadence and on/off state along, for the same reason cadenceRequest carries
 * the depth: the PUT is the whole setting.
 */
export function retainRequest(value: number, current: BackupSchedule | null): BackupScheduleRequest {
  const retain = Number.isInteger(value) && value >= 1 ? value : retainValue(current);
  if (!current || !current.enabled) return { enabled: false, retain };
  const every = current.every ?? current.defaultEvery;
  return every ? { enabled: true, every, retain } : { enabled: true, retain };
}

/**
 * The helper text under the retention control. It says the one thing an
 * operator lowering the number needs to hear before they do it: the oldest
 * generations go on the NEXT run, not now — prune is a step of a run, and it
 * converges the disk on the depth whatever it held before.
 */
export function retainHelpText(schedule: BackupSchedule | null): string {
  const n = retainValue(schedule);
  return `${n} generation${n === 1 ? '' : 's'} kept on the target, newest first. Lowering it prunes the oldest on the next backup run; nothing is deleted until then.`;
}

/**
 * How many app volumes a run captured, as a sentence fragment for the scope
 * tooltip. Zero is spelled out rather than rendered as an empty string —
 * "0 app volumes captured" is the fact; "" is an omission.
 */
export function appVolumeSummary(captured: number): string {
  return `${captured} app volume${captured === 1 ? '' : 's'} captured`;
}
