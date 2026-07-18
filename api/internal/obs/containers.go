package obs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ContainersClient is a small shim that summarizes the cAdvisor metrics
// Alloy publishes to VictoriaMetrics — CPU%, memory, restarts — into
// the row shape the NodeDetailDrawer's Containers tab renders.
//
// Since Slice 1.2b, a collector runs on every Docker-capable node and the
// controlplane's own Alloy is tagged too (§3.10 piece 5), all stamping
// samples with `node_id`. List() filters on that label, so each node's drawer
// shows that node's containers. An empty nodeID returns every container
// (the pre-1.2b behavior).
type ContainersClient struct {
	sup    Supervisor
	client *http.Client
}

// ContainersClientConfig is the constructor input.
type ContainersClientConfig struct {
	// Supervisor must report a non-empty VMBaseURL() once VM is up.
	Supervisor Supervisor
	// HTTPClient is the transport used for the query. Defaults to a
	// 5s client — three instant queries; should be quick.
	HTTPClient *http.Client
}

// NewContainersClient constructs a ContainersClient. Supervisor required.
func NewContainersClient(cfg ContainersClientConfig) (*ContainersClient, error) {
	if cfg.Supervisor == nil {
		return nil, errors.New("obs: ContainersClient requires a Supervisor")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &ContainersClient{sup: cfg.Supervisor, client: client}, nil
}

// Container is one row in the drawer's Containers table. CPU is a 1-min
// rate of cAdvisor's user+system seconds (so 0.5 ≈ half a core). Mem is
// the working set in bytes. Restarts is the lifetime count cAdvisor
// reports for the container.
type Container struct {
	Name     string  `json:"name"`
	Image    string  `json:"image"`
	CPU      float64 `json:"cpuCores"` // fractional cores; 1.0 = one full core
	MemBytes float64 `json:"memBytes"`
	Restarts int64   `json:"restarts"`
}

// List returns one Container per running container cAdvisor sees on the
// given node. Sorted by CPU descending so the busiest container lands at the
// top of the table. A non-empty nodeID filters on the `node_id` label; an
// empty one returns every container across the cluster.
func (c *ContainersClient) List(ctx context.Context, nodeID string) ([]Container, error) {
	base := c.sup.VMBaseURL()
	if base == "" {
		return nil, errors.New("obs.Containers: VM base url empty (obs not started?)")
	}
	// Three instant queries: CPU rate, memory, restart count. cAdvisor
	// uses "name" for the human-readable container name and "image" for
	// the image ref. We rate-over-1m for CPU so the value is intuitive
	// ("0.5 cores"); 30s and 5m are alternatives if 1m turns out to be
	// too jumpy on the actual cluster.
	//
	// Since Slice 1.2b every node's collector (and the controlplane's own
	// Alloy, §3.10 piece 5) tags samples with node_id, so a non-empty nodeID
	// narrows each query to that node's containers. strconv.Quote escapes the
	// operator-supplied value into a safe PromQL string literal. Empty nodeID
	// (no filter) still returns everything — the pre-1.2b behavior.
	sel := `name!=""`
	if nodeID != "" {
		sel += `,node_id=` + strconv.Quote(nodeID)
	}
	cpuQ := `sum by (name, image) (rate(container_cpu_usage_seconds_total{` + sel + `}[1m]))`
	memQ := `sum by (name, image) (container_memory_working_set_bytes{` + sel + `})`
	resQ := `sum by (name, image) (container_start_time_seconds{` + sel + `})` // proxy for restarts; see doc

	type cell struct {
		Container
	}
	rows := make(map[string]*Container) // keyed by "name"
	add := func(key string, mut func(*Container)) {
		k := key
		c, ok := rows[k]
		if !ok {
			c = &Container{}
			rows[k] = c
		}
		mut(c)
	}

	for _, qd := range []struct {
		query string
		apply func(name, image string, v float64, c *Container)
	}{
		{cpuQ, func(name, image string, v float64, c *Container) {
			c.Name, c.Image, c.CPU = name, image, v
		}},
		{memQ, func(name, image string, v float64, c *Container) {
			if c.Name == "" {
				c.Name, c.Image = name, image
			}
			c.MemBytes = v
		}},
		{resQ, func(name, image string, v float64, c *Container) {
			if c.Name == "" {
				c.Name, c.Image = name, image
			}
			// container_start_time_seconds is the start epoch; it's a
			// reasonable proxy for "has this container restarted" — when
			// VM has multiple distinct values per name over time, the
			// container restarted. v0 just surfaces the latest as a
			// timestamp; the operator can spot fresh restarts by
			// comparing to other containers. Real restart counts come
			// from Docker's events API in a future slice.
			c.Restarts = int64(v)
		}},
	} {
		results, err := c.queryInstant(ctx, base, qd.query)
		if err != nil {
			return nil, fmt.Errorf("vm query %q: %w", qd.query, err)
		}
		for _, r := range results {
			name := r.metric["name"]
			image := r.metric["image"]
			if name == "" {
				continue
			}
			add(name, func(cc *Container) { qd.apply(name, image, r.value, cc) })
		}
	}

	out := make([]Container, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CPU != out[j].CPU {
			return out[i].CPU > out[j].CPU
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// queryResult is one (metric, value) pair from VM's instant query
// response — small enough to inline rather than depend on an external
// Prometheus client library.
type queryResult struct {
	metric map[string]string
	value  float64
}

// queryInstant hits VM's /api/v1/query (no range — just "now") and
// decodes the standard vector response shape:
//
//	{"status":"success","data":{"resultType":"vector","result":[
//	   {"metric":{...},"value":[<ts_s>, "<value_str>"]}, ...]}}
func (c *ContainersClient) queryInstant(ctx context.Context, base, expr string) ([]queryResult, error) {
	params := url.Values{}
	params.Set("query", expr)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		base+"/api/v1/query?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vm query HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var env struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("vm response decode: %w", err)
	}
	if env.Status != "success" {
		return nil, fmt.Errorf("vm status=%q error=%q", env.Status, env.Error)
	}
	out := make([]queryResult, 0, len(env.Data.Result))
	for _, r := range env.Data.Result {
		s, ok := r.Value[1].(string)
		if !ok {
			continue
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			continue
		}
		out = append(out, queryResult{metric: r.Metric, value: v})
	}
	return out, nil
}
