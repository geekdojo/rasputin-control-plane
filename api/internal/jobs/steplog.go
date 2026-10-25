package jobs

import "log/slog"

// LogStep writes one event to both of a step's pipelines: the job's step log,
// which a person reads on the Tasks page and so gets only msg, which must be
// safe text, and log, which gets msg with the job's id and attrs, the fields
// an operator acts on. A StepCtx with no Log writes to log alone.
func LogStep(log *slog.Logger, sc *StepCtx, level slog.Level, msg string, attrs ...any) {
	log.Log(sc.Ctx, level, msg, append([]any{"job_id", sc.JobID}, attrs...)...)
	if sc.Log == nil {
		return
	}
	lvl := "info"
	switch {
	case level >= slog.LevelError:
		lvl = "error"
	case level >= slog.LevelWarn:
		lvl = "warn"
	}
	sc.Log(lvl, msg)
}
