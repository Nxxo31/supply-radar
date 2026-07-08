# supply-radar — Contexto del agente

## Proyecto
Scanner de supply chain en Go. V1.1 activa con markdown reporter.
GitHub: https://github.com/Nxxo31/supply-radar

## Stack
- Go 1.23
- Build: `go build -o supply-radar .`
- Test: `go test ./...`
- Binarios compilados: supply-radar, supply-radar-bin (no commitear)

## Reglas críticas
- No commitear binarios
- `go vet ./...` antes de commit

## Loop de trabajo
1. `cat PROJECT.md` → verificar estado
2. Implementar → `go build && go test ./...`
3. Commit atómico en español → push
