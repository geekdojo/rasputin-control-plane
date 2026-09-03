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
  warning?: string;
}): string {
  const parts = [appVolumeSummary(run.appVolumesCaptured)];
  const skipped = run.appVolumesSkipped ?? 0;
  if (skipped > 0) parts.push(`${skipped} NOT captured`);
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

/** The PUT body for a cadence the operator picked. */
export function cadenceRequest(value: string): { enabled: boolean; every?: string } {
  if (value === CADENCE_OFF) return { enabled: false };
  return { enabled: true, every: value };
}

/**
 * How many app volumes a run captured, as a sentence fragment for the scope
 * tooltip. Zero is spelled out rather than rendered as an empty string —
 * "0 app volumes captured" is the fact; "" is an omission.
 */
export function appVolumeSummary(captured: number): string {
  return `${captured} app volume${captured === 1 ? '' : 's'} captured`;
}
