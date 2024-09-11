module github.com/bitcoinschema/go-bap

go 1.22

toolchain go1.22.5

require (
	github.com/bitcoin-sv/go-sdk v1.1.7
	github.com/bitcoinschema/go-aip v0.2.3
	github.com/bitcoinschema/go-bob v0.4.3
	github.com/bitcoinschema/go-bpu v0.1.3
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.21.0 // indirect
)

// BAP has breaking changes upgrading to new version of AIP from sub packages BOB and BPU
// replace github.com/bitcoinschema/go-aip => github.com/bitcoinschema/go-aip v0.1.9

replace github.com/bitcoinschema/go-aip => ../go-aip

replace github.com/bitcoinschema/go-bob => ../go-bob

replace github.com/bitcoinschema/go-bpu => ../go-bpu

replace github.com/bitcoin-sv/go-sdk => ../../go-sdk
