package obs

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/geekdojo/rasputin-control-plane/tileschema"
)

// validateImages rejects any reference that is not digest-pinned, naming the
// environment variable an operator would have used to set it.
//
// It reports EVERY bad reference rather than the first. An operator pointing a
// dev stack at local builds typically overrides several at once, and a
// one-at-a-time gate turns that into as many restarts as they set.
func validateImages(byEnvVar map[string]string) error {
	names := make([]string, 0, len(byEnvVar))
	for k := range byEnvVar {
		names = append(names, k)
	}
	sort.Strings(names)

	var bad []string
	for _, env := range names {
		if err := tileschema.ValidateImagePin(byEnvVar[env]); err != nil {
			bad = append(bad, fmt.Sprintf("%s=%q: %v", env, byEnvVar[env], err))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("obs supervisor: image reference must be digest-pinned (name:tag@sha256:...): %s",
		strings.Join(bad, "; "))
}

// images returns every image reference this stack will run, in a stable order,
// skipping services that are switched off.
func (s *DockerComposeSupervisor) images() []string {
	out := []string{s.cfg.VMImage, s.cfg.AlloyImage}
	if s.lokiEnabled() {
		out = append(out, s.cfg.LokiImage)
	}
	if s.grafanaEnabled() {
		out = append(out, s.cfg.GrafanaImage)
	}
	if s.vmalertEnabled() {
		out = append(out, s.cfg.VMAlertImage)
	}
	sort.Strings(out)
	return out
}

// missingImages asks the daemon which of this stack's images are absent from
// the local store. The reference is digest-pinned, so `docker image inspect`
// answering at all means the daemon holds THAT image and not merely something
// wearing the same tag.
//
// An error here means the question could not be asked -- the daemon is down, or
// the CLI is not where we think it is -- which is different from "the image is
// missing" and is reported as such by the caller.
func (s *DockerComposeSupervisor) missingImages(ctx context.Context) ([]string, error) {
	var missing []string
	for _, img := range s.images() {
		// `docker image inspect` exits non-zero for an unknown image and zero
		// for a known one, so the error is the answer. A daemon that is down
		// fails every lookup, which would read as "everything is missing" --
		// so probe the daemon once first and report that separately.
		if _, err := s.runner(ctx, s.cfg.DockerBin, "image", "inspect", "--format", "{{.Id}}", img); err != nil {
			missing = append(missing, img)
		}
	}
	if len(missing) == len(s.images()) && len(missing) > 0 {
		if _, err := s.runner(ctx, s.cfg.DockerBin, "version", "--format", "{{.Server.Version}}"); err != nil {
			return nil, fmt.Errorf("docker daemon is not answering: %w", err)
		}
	}
	return missing, nil
}
