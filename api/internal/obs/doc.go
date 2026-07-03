// Package obs lifecycle-manages the local observability sidecars:
// VictoriaMetrics, Loki, Grafana, Grafana Alloy. They run as containers
// under the same engine that hosts user apps.
//
// See projects/rasputin/design/control-plane/architecture.md §7.6
// in the geekdojo-brain.
package obs
