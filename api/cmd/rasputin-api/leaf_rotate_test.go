package main

import (
	"bytes"
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"

	"github.com/geekdojo/rasputin-control-plane/api/internal/apps"
	"github.com/geekdojo/rasputin-control-plane/api/internal/tlsca"
)

// TC-825-08: the rotator main wires hands the leaf key beside the command, as
// a secret.Value, never inside it; and the commit it returns writes exactly
// that Value's bytes to the app's key file.
func TestAppLeafRotator_KeyTravelsBesideTheCommand(t *testing.T) {
	ca, err := tlsca.EnsureMeshCA(t.TempDir(), "home1")
	if err != nil {
		t.Fatalf("mesh CA: %v", err)
	}
	leafRoot := t.TempDir()
	rotate := newAppLeafRotator(ca, leafRoot, "home1")
	app := &apps.App{ID: leafTestAppID, Name: "jellyfin", PublishedPort: 8096, ExposeLAN: true}

	leaf, renewed, commit, err := rotate(app)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer leaf.Key.Destroy()
	if !renewed || commit == nil {
		t.Fatalf("a first rotation must mint and offer a commit: renewed=%v commit-nil=%v", renewed, commit == nil)
	}
	if len(leaf.Cmd.KeyPEM) != 0 {
		t.Fatal("the delivery command carries the key; it must travel beside it as a secret.Value")
	}
	if leaf.Key.Len() == 0 {
		t.Fatal("the leaf has no key")
	}
	if _, err := tls.X509KeyPair(leaf.Cmd.CertPEM, leaf.Key.Reveal()); err != nil {
		t.Fatalf("the key does not pair with the command's certificate: %v", err)
	}
	if leaf.Cmd.AppID != app.ID || leaf.Cmd.UpstreamPort != 8096 || leaf.Cmd.LANFQDN == "" || leaf.Cmd.TailnetFQDN == "" {
		t.Errorf("the command's route is not the app's: %+v", leaf.Cmd)
	}

	if err := commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	onDisk, err := os.ReadFile(tlsca.LeafPathsIn(filepath.Join(leafRoot, app.ID)).KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, leaf.Key.Reveal()) {
		t.Fatal("the committed key file is not the leaf's key")
	}
}
