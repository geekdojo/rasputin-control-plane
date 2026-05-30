module github.com/geekdojo/rasputin-control-plane/agent

go 1.23

require (
	github.com/geekdojo/rasputin-control-plane/proto v0.0.0-00010101000000-000000000000
	github.com/nats-io/nats-server/v2 v2.10.20
	github.com/nats-io/nats.go v1.51.0
	github.com/shirou/gopsutil/v4 v4.24.8
)

require (
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/jwt/v2 v2.8.1 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/geekdojo/rasputin-control-plane/proto => ../proto
