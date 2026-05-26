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

export type NodeRole = 'controlplane' | 'firewall' | 'compute' | 'storage';
export type NodeStatus = 'online' | 'stale' | 'offline';
export type InventoryChange =
  | 'added'
  | 'online'
  | 'stale'
  | 'offline'
  | 'updated';

export interface Node {
  id: string;
  role: NodeRole;
  hostname: string;
  agentVersion: string;
  capabilities?: string[];
  metadata?: Record<string, unknown>;
  firstSeen: string;
  lastSeen: string;
  status: NodeStatus;
}

export interface InventoryChangeEvent {
  change: InventoryChange;
  node: Node;
  ts: string;
}
