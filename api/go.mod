module github.com/geekdojo/rasputin-control-plane/api

go 1.26.0

require (
	github.com/coder/websocket v1.8.15
	github.com/geekdojo/rasputin-control-plane/artifactsig v0.0.0-00010101000000-000000000000
	github.com/geekdojo/rasputin-control-plane/proto v0.0.0-00010101000000-000000000000
	github.com/geekdojo/rasputin-control-plane/tileschema v0.0.0-00010101000000-000000000000
	github.com/go-webauthn/webauthn v0.18.0
	github.com/miekg/dns v1.1.73
	github.com/nats-io/jwt/v2 v2.8.2
	github.com/nats-io/nats-server/v2 v2.14.6
	github.com/nats-io/nats.go v1.53.1
	github.com/nats-io/nkeys v0.4.16
	github.com/oklog/ulid/v2 v2.1.2
	golang.org/x/crypto v0.55.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.57.0
)

require (
	github.com/antithesishq/antithesis-sdk-go v0.7.2-default-no-op // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/x v0.3.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/smallstep/pkcs7 v0.2.3 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/geekdojo/rasputin-control-plane/proto => ../proto

replace github.com/geekdojo/rasputin-control-plane/tileschema => ../tileschema

replace github.com/geekdojo/rasputin-control-plane/artifactsig => ../artifactsig
