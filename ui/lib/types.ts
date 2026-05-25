export type JobStatus =
  | 'queued'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'cancelled';

export type StepStatus =
  | 'pending'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'compensated';

export interface Job {
  id: string;
  kind: string;
  spec: unknown;
  status: JobStatus;
  createdBy: string;
  createdAt: string;
  startedAt?: string;
  finishedAt?: string;
  parentId?: string;
  error?: string;
}

export interface JobStep {
  jobId: string;
  seq: number;
  name: string;
  status: StepStatus;
  startedAt?: string;
  finishedAt?: string;
  attempt: number;
  result?: unknown;
  error?: string;
}

export interface JobEvent {
  id?: number; // present on REST replies, absent on the wire
  type: string;
  jobId: string;
  ts: string;
  data?: unknown;
}
