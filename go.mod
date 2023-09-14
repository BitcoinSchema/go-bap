module github.com/bitcoinschema/go-bap

go 1.18

require (
	github.com/bitcoinschema/go-aip v0.2.0
	github.com/bitcoinschema/go-bitcoin v0.3.20
	github.com/bitcoinschema/go-bob v0.4.0
	github.com/bitcoinschema/go-bpu v0.1.0
	github.com/bitcoinsv/bsvutil v0.0.0-20181216182056-1d77cf353ea9
	github.com/libsv/go-bt/v2 v2.2.5
)

require (
	github.com/bitcoinsv/bsvd v0.0.0-20190609155523-4c29707f7173 // indirect
	github.com/bitcoinsv/bsvlog v0.0.0-20181216181007-cb81b076bf2e // indirect
	github.com/libsv/go-bk v0.1.6 // indirect
	github.com/libsv/go-bt v1.0.8 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.13.0 // indirect
)

// BAP has breaking changes upgrading to new version of AIP from sub packages BOB and BPU
// replace github.com/bitcoinschema/go-aip => github.com/bitcoinschema/go-aip v0.1.9
