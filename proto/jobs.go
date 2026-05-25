package proto

import (
	"encoding/json"
	"time"
)

// JobEventType enumerates the lifecycle events emitted on
// rasputin.job.<id>.events.
type JobEventType string

const (
	JobCreated       JobEventType = "created"
	JobStarted       JobEventType = "started"
	JobStepStarted   JobEventType = "step_started"
	JobStepSucceeded JobEventType = "step_succeeded"
	JobStepFailed    JobEventType = "step_failed"
	JobStepRetrying  JobEventType = "step_retrying"
	JobSucceeded     JobEventType = "succeeded"
	JobFailed        JobEventType = "failed"
	JobLog           JobEventType = "log"
)

// JobEvent is the message published to rasputin.job.<id>.events.
// Data is event-type-specific (see comments below).
type JobEvent struct {
	Type  JobEventType    `json:"type"`
	JobID string          `json:"jobId"`
	Ts    time.Time       `json:"ts"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// StepEventData accompanies JobStepStarted, JobStepSucceeded,
// JobStepFailed, and JobStepRetrying events.
type StepEventData struct {
	Seq     int             `json:"seq"`
	Name    string          `json:"name"`
	Attempt int             `json:"attempt,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// LogEventData accompanies JobLog events.
type LogEventData struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}
