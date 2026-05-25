package jobs

import (
	"encoding/json"
	"time"
)

// Status enumerates the possible states of a Job.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// StepStatus enumerates the possible states of a JobStep.
type StepStatus string

const (
	StepPending     StepStatus = "pending"
	StepRunning     StepStatus = "running"
	StepSucceeded   StepStatus = "succeeded"
	StepFailed      StepStatus = "failed"
	StepCompensated StepStatus = "compensated"
)

// Job is the durable record of a state-changing operation.
type Job struct {
	ID         string          `json:"id"`
	Kind       string          `json:"kind"`
	Spec       json.RawMessage `json:"spec"`
	Status     Status          `json:"status"`
	CreatedBy  string          `json:"createdBy"`
	CreatedAt  time.Time       `json:"createdAt"`
	StartedAt  *time.Time      `json:"startedAt,omitempty"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
	ParentID   *string         `json:"parentId,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// JobStep is the durable record of one step within a Job.
type JobStep struct {
	JobID      string          `json:"jobId"`
	Seq        int             `json:"seq"`
	Name       string          `json:"name"`
	Status     StepStatus      `json:"status"`
	StartedAt  *time.Time      `json:"startedAt,omitempty"`
	FinishedAt *time.Time      `json:"finishedAt,omitempty"`
	Attempt    int             `json:"attempt"`
	Result     json.RawMessage `json:"result,omitempty"`
	Error      string          `json:"error,omitempty"`
}

// JobEvent is the durable record of a lifecycle event, mirrored on NATS at
// rasputin.job.<id>.events.
type JobEvent struct {
	ID    int64           `json:"id"`
	JobID string          `json:"jobId"`
	Ts    time.Time       `json:"ts"`
	Type  string          `json:"type"`
	Data  json.RawMessage `json:"data,omitempty"`
}
