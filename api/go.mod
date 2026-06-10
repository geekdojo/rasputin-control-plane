module github.com/geekdojo/rasputin-control-plane/api

go 1.26.0

require (
	github.com/coder/websocket v1.8.12
	github.com/geekdojo/rasputin-control-plane/proto v0.0.0-00010101000000-000000000000
	github.com/go-webauthn/webauthn v0.11.2
	github.com/nats-io/nats-server/v2 v2.11.17
	github.com/nats-io/nats.go v1.51.0
	github.com/oklog/ulid/v2 v2.1.0
	modernc.org/sqlite v1.33.1
)

require (
	github.com/antithesishq/antithesis-sdk-go v0.7.0-default-no-op // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-webauthn/x v0.1.14 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/klauspost/compress v1.18.5 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/nats-io/jwt/v2 v2.8.1 // indirect
	github.com/nats-io/nkeys v0.4.15 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	modernc.org/gc/v3 v3.0.0-20240107210532-573471604cb6 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
	modernc.org/strutil v1.2.0 // indirect
	modernc.org/token v1.1.0 // indirect
)

replace github.com/geekdojo/rasputin-control-plane/proto => ../proto
