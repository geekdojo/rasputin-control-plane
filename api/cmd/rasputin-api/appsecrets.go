package main

import (
	"context"
	"log/slog"
	"path/filepath"

	"github.com/geekdojo/rasputin-control-plane/api/internal/appsecret"
	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/logkit"
)

// loadAppSecrets loads the cluster's app-secret seed from trustDir, minting it
// on first start, and returns it with the HKDF source the deploy-family
// workflows resolve ${secret:} tokens through. main still needs the seed
// itself, for the fingerprint key.
//
// It fails closed. A seed that does not load means no app secret can be
// derived, and a start that could not read an EXISTING seed must not carry on
// (see main), so it logs FATAL and calls exit(1). exit is os.Exit in main; the
// nils returned after it are never used. Neither record carries seed bytes:
// EnsureSeed's errors name the path and the parse failure only.
func loadAppSecrets(ctx context.Context, logger *slog.Logger, exit func(int), trustDir string) (*appsecret.Seed, *appsecret.HKDFSource) {
	path := filepath.Join(trustDir, appsecret.SeedFileName)
	seed, err := appsecret.EnsureSeed(trustDir)
	var source *appsecret.HKDFSource
	if err == nil {
		source, err = appsecret.NewHKDFSource(seed)
	}
	if err != nil {
		logger.Log(ctx, logkit.LevelFatal, "rasputin-api: app-secret seed did not load", "path", path, "err", err.Error())
		exit(1)
		return nil, nil
	}
	logger.Info("rasputin-api: app-secret seed loaded", "path", path, "derivation_version", seed.DerivationVersion())
	return seed, source
}

// workflowOrExit returns the unwrapper main registers each refusable workflow
// through: a constructor that refused its wiring is logged FATAL and exits 1,
// so the api never comes up with a saga it cannot run. exit is os.Exit in
// main; the zero workflow returned after it is never registered.
//
// It is curried because Go will not pass a two-valued call alongside another
// argument, so must(apps.DeployWorkflow(...)) is the shape main can write.
func workflowOrExit(ctx context.Context, logger *slog.Logger, exit func(int)) func(jobs.Workflow, error) jobs.Workflow {
	return func(w jobs.Workflow, err error) jobs.Workflow {
		if err != nil {
			logger.Log(ctx, logkit.LevelFatal, "rasputin-api: app workflow refused its wiring", "err", err.Error())
			exit(1)
			return jobs.Workflow{}
		}
		return w
	}
}
