package api

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/geekdojo/rasputin-control-plane/api/internal/jobs"
	"github.com/geekdojo/rasputin-control-plane/proto"
)

// POST /api/mesh/enroll/{nodeId} targets a valid, registered node: 400 for an
// id that is not a node id, 404 for a node that is not in inventory, and no job
// is queued for either.
func TestHandleMeshEnrollNode_RequiresValidRegisteredNode(t *testing.T) {
	f := newAPIFixture(t)
	c := f.authenticate(t)
	f.runner.Register(jobs.Workflow{Kind: "mesh.enroll_node"})

	now := time.Now().UTC()
	if err := f.inv.Insert(f.ctx, &proto.Node{ID: "alpha", Role: proto.RoleCompute, FirstSeen: now, LastSeen: now}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	for _, id := range []string{"*", ">", "a.b", "a b", "Alpha", "node_1", "-alpha", "alpha-", strings.Repeat("a", 64)} {
		w := f.do(t, http.MethodPost, "/api/mesh/enroll/"+url.PathEscape(id), "", c)
		if w.Code != http.StatusBadRequest {
			t.Errorf("enroll %q = %d, want 400 (body %s)", id, w.Code, w.Body.String())
		}
	}

	if w := f.do(t, http.MethodPost, "/api/mesh/enroll/beta", "", c); w.Code != http.StatusNotFound {
		t.Errorf("enroll of an unregistered node = %d, want 404 (body %s)", w.Code, w.Body.String())
	}

	queued, err := f.srv.store.ListJobsByKind(f.ctx, "mesh.enroll_node", 100)
	if err != nil {
		t.Fatalf("ListJobsByKind: %v", err)
	}
	if len(queued) != 0 {
		t.Fatalf("refused enrolls queued %d job(s), want 0", len(queued))
	}

	if w := f.do(t, http.MethodPost, "/api/mesh/enroll/alpha", "", c); w.Code != http.StatusAccepted {
		t.Errorf("enroll of a registered node = %d, want 202 (body %s)", w.Code, w.Body.String())
	}
}
