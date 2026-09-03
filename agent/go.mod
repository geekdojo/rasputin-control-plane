module github.com/geekdojo/rasputin-control-plane/agent

go 1.26.0

require (
	github.com/geekdojo/rasputin-control-plane/artifactsig v0.0.0-00010101000000-000000000000
	github.com/geekdojo/rasputin-control-plane/proto v0.0.0-00010101000000-000000000000
	github.com/geekdojo/rasputin-control-plane/tileschema v0.0.0-00010101000000-000000000000
	github.com/nats-io/nats-server/v2 v2.14.6
	github.com/nats-io/nats.go v1.53.1
	github.com/shirou/gopsutil/v4 v4.26.8
	golang.org/x/sys v0.47.0
)

require (
	github.com/antithesishq/antithesis-sdk-go v0.7.2-default-no-op // indirect
	github.com/ebitengine/purego v0.10.2 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/jwt/v2 v2.8.2 // indirect
	github.com/nats-io/nkeys v0.4.16 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/smallstep/pkcs7 v0.2.3 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/geekdojo/rasputin-control-plane/proto => ../proto

replace github.com/geekdojo/rasputin-control-plane/artifactsig => ../artifactsig

replace github.com/geekdojo/rasputin-control-plane/tileschema => ../tileschema
