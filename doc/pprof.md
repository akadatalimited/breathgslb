# pprof Profiling

BreathGSLB can expose Go's built-in [pprof](https://pkg.go.dev/net/http/pprof)
profiles for on-demand performance investigation.

## Enable

Start the daemon with `-debug-pprof` to launch a debug HTTP server on
`localhost:6060`:

```bash
breathgslb -debug-pprof [other flags]
```

## Endpoints

All handlers live under `http://localhost:6060/debug/pprof/`:

| Path | Purpose | Example call |
|------|---------|--------------|
| `/` | Index of available profiles | `curl http://localhost:6060/debug/pprof/` |
| `profile?seconds=30` | CPU profile | `go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30` |
| `heap` | Heap (memory) profile | `go tool pprof http://localhost:6060/debug/pprof/heap` |
| `goroutine` | Goroutine stack dumps | `curl http://localhost:6060/debug/pprof/goroutine?debug=1` |
| `block`, `mutex`, `threadcreate` | Blocking, mutex contention, thread creation profiles | `go tool pprof http://localhost:6060/debug/pprof/block` |
| `trace?seconds=5` | Execution trace | `curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=5` (view with `go tool trace trace.out`) |

## Typical workflow

1. **Enable profiling** by starting BreathGSLB with `-debug-pprof`.
2. **Gather data** from the appropriate endpoint using `go tool pprof` or `curl`.
3. **Analyse** via the interactive CLI or web UI: `go tool pprof -http=:8081 <profile>`.
4. **Inspect traces** with `go tool trace trace.out` when a trace was captured.

The debug server only listens on `localhost` and is intended for temporary
analysis in controlled environments.

