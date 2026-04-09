# Repository Guidelines

## Project Structure & Module Organization

This repository is centered on the Go module in `src/`. Core server code lives in `src/*.go`, with focused packages under `src/config`, `src/dnsserver`, `src/healthcheck`, and `src/logging`. Tests sit beside the code as `*_test.go`. The optional web and licensing tooling lives in `src/web` and `src/cmd/{licensegen,licensectl}`. Top-level `man/`, `services/`, `scripts/`, and `src/doc/` contain manuals, service units, helper scripts, and generated docs. Treat `src/vendor/` and top-level `vendor/` as managed dependency trees; only update them with dependency changes.

## Build, Test, and Development Commands

Run commands from the repository root unless noted.

- `make build`: build the main `breathgslb` binary from `./src`.
- `make test`: run `go test -race ./...` in `src/`; this is the main CI gate.
- `make fmt`: apply `gofmt` via `go fmt ./...`.
- `make vet`: run `go vet ./...`.
- `make web`: build the web UI binary in `src/web/`.
- `make vendor`: refresh `go.mod`, `go.sum`, and vendored dependencies.
- `make docs`: regenerate the PDF manual from `man/` and `src/doc/`.

For targeted work, use `go -C src test -run TestName ./...`.

## Coding Style & Naming Conventions

Follow standard Go formatting and import ordering; `make fmt` is the source of truth. Use tabs as emitted by `gofmt`, keep packages lowercase, and use descriptive exported names in PascalCase. Prefer small, file-focused helpers named by responsibility, such as `health_functions.go` or `zone_index.go`. Keep configuration examples and service files in sync with behavior changes.

## Testing Guidelines

Add or update `*_test.go` files beside the code you change. Favor table-driven tests for DNS, config parsing, and health-selection logic. Integration-style tests may rely on `tests.config`; keep those assumptions explicit in test comments. Before opening a PR, run `make test` and any targeted `go test -run ...` cases covering your change.

## Commit & Pull Request Guidelines

Recent history favors short, imperative subjects such as `Fix CI to run Go commands from src module directory`. Keep commit titles concise, one change per commit where practical, and include docs/config updates with behavior changes. PRs should explain the user-visible impact, list verification steps, reference related issues, and include sample config, API, or UI output when the change affects operators.
