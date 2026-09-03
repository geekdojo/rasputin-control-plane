module github.com/geekdojo/rasputin-control-plane/backupxfer

go 1.26

require (
	github.com/geekdojo/rasputin-control-plane/proto v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.50.0
)

require golang.org/x/sys v0.43.0 // indirect

replace github.com/geekdojo/rasputin-control-plane/proto => ../proto
