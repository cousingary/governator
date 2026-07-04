# Contributing

## Build and test

Use Go 1.26 or newer.

```sh
gofmt -w ./cmd ./internal
go vet ./...
go test -race ./...
go build ./cmd/gov
```

Run focused fuzz targets after changing parsers or command classification. Integration examples under `integrations/` must also pass their formatter/linter.

## Pull requests

1. Keep each PR scoped to one behavior and include deterministic tests for every changed enforcement path.
2. State threat-model impact and compatibility changes; never include credentials, personal paths, generated binaries, or paid model calls.
