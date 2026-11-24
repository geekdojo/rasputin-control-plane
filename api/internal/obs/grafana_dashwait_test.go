//go:build linux || supervisor

package obs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// starterDashboardUID is the fixed uid in the provisioned cluster-overview
// dashboard JSON.
const starterDashboardUID = "rasputin-cluster-overview"

// dashWaitUser is the name the waits below assert to Grafana's auth proxy.
// It is an ordinary auto-signed-up Viewer, like every test's user.
const dashWaitUser = "alice"

// waitForProvisionedDashboard waits until Grafana's own search lists the
// starter dashboard. That is the checkable fact every test that reads a
// dashboard waits on before it does.
//
// Why search and not Grafana's database: from Grafana 13 provisioned
// dashboards live in its unified storage, and the legacy dashboard and
// dashboard_provisioning tables the waits used to read stay empty (measured
// on 13.3.1: no row after four minutes, while search listed both provisioned
// dashboards on its first answer). On 11.5.1 an authenticated request made
// before provisioning had committed hid the dashboard from search for a
// minute or more; on 13.3.1 the first search, made as soon as Start returned,
// listed it. Either way this waits on what Grafana reports, so after it a
// test reads once, with no deadline deciding its outcome.
//
// The deadline bounds only how long provisioning may take at all.
func waitForProvisionedDashboard(t *testing.T, sup *DockerComposeSupervisor, within time.Duration) {
	t.Helper()
	waitForDashboardInSearch(t, sup, starterDashboardUID, within)
}

// waitForDashboardInSearch is waitForProvisionedDashboard for the dashboard
// with uid.
func waitForDashboardInSearch(t *testing.T, sup *DockerComposeSupervisor, uid string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	var last string
	for {
		found, seen, err := dashboardInSearch(sup, uid)
		if err == nil && found {
			return
		}
		last = seen
		if err != nil {
			last = err.Error()
		}
		if time.Now().After(deadline) {
			t.Fatalf("Grafana's search never listed dashboard %q within %s (last answer: %.400s)",
				uid, within, last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// dashboardInSearch asks Grafana's search for uid, through whatever transport
// the supervisor says reaches Grafana. It reports whether the answer lists
// uid, and the answer itself for a failure message. A transport error is
// returned, not fatal: Grafana may still be starting or restarting.
func dashboardInSearch(sup *DockerComposeSupervisor, uid string) (bool, string, error) {
	code, body, err := grafanaFetch(sup, "/api/search?dashboardUIDs="+url.QueryEscape(uid))
	if err != nil {
		return false, "", err
	}
	if code != http.StatusOK {
		return false, fmt.Sprintf("%d %s", code, body), nil
	}
	var hits []struct {
		UID string `json:"uid"`
	}
	if err := json.Unmarshal([]byte(body), &hits); err != nil {
		return false, body, fmt.Errorf("search answer: %w", err)
	}
	for _, h := range hits {
		if h.UID == uid {
			return true, body, nil
		}
	}
	return false, body, nil
}

// grafanaFetch GETs path from Grafana as dashWaitUser. The client's timeout
// bounds this one call.
func grafanaFetch(sup *DockerComposeSupervisor, path string) (int, string, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	if tr := sup.GrafanaTransport(); tr != nil {
		c.Transport = tr
	}
	req, err := http.NewRequest(http.MethodGet, sup.GrafanaBaseURL()+path, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-Webauth-User", dashWaitUser)
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, "", err
	}
	return resp.StatusCode, string(b), nil
}
