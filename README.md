## go-bap

Library for working with [Bitcoin Attestation Protocol](https://github.com/icellan/bap) in Go

## Usage

```go
bapData = bap.New()
bapData.FromTape(tape)
```

the data will be of this type

```go
type Data struct {
	Type     string `json:"type,omitempty" bson:"type,omitempty"`
	URNHash  string `json:"urnHash,omitempty" bson:"urnHash,omitempty"`
	IDKey string `json:"IDKey,omitempty" bson:"IDKey,omitempty"`
	Address  string `json:"address,omitempty" bson:"address,omitempty"`
	Sequence uint8  `json:"sequence" bson:"sequence"`
}
```

## Helper Methods

`CreateIdentity`

`CreateAttestation`

## ToDo

- `CreateRevocation`
- tests
