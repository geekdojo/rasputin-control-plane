module github.com/geekdojo/rasputin-control-plane/agent

go 1.23

require (
	github.com/geekdojo/rasputin-control-plane/proto v0.0.0-00010101000000-000000000000
	github.com/nats-io/nats.go v1.37.0
)

require (
	github.com/klauspost/compress v1.17.2 // indirect
	github.com/nats-io/nkeys v0.4.7 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	golang.org/x/crypto v0.18.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
)

replace github.com/geekdojo/rasputin-control-plane/proto => ../proto
