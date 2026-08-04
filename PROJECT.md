# PROJECT.md — Supply Radar

> **Estado:** Activo | **Versión:** 1.2.0 | **Última actualización:** 2026-08-03

---

## 🎯 Objetivo Principal

CLI de supply chain security que escanea dependencias Go y npm, consulta vulnerabilidades en OSV, genera SBOMs (SPDX/CycloneDX) y reporta riesgos sin fricción — autónomo, offline-capable, sin dependencias externas.

## 🎯 Objetivos Secundarios

1. Soportar múltiples ecosistemas (Go, npm, PyPI, Rust) vía parsers extensibles
2. Generar SBOMs en formatos SPDX y CycloneDX para auditoría de cadena de suministro
3. Integrarse en CI/CD con exit codes útiles y reporter SARIF para GitHub Code Scanning
4. Escanear monorepos recursivamente detectando todos los manifests lockfile-per-servicio

---

## 📐 Arquitectura

### Stack Tecnológico

| Capa | Tecnología | Versión | Propósito |
|------|-----------|---------|-----------|
| Lenguaje | Go | 1.23+ | Concurrencia nativa, binario único distribuible |
| CLI | flag stdlib | 1.23 | Parsing de argumentos (Cobra era overkill para MVP) |
| HTTP | net/http stdlib | 1.23 | Cliente a api.osv.dev |
| Testing | testing stdlib | 1.23 | Tests unitarios por paquete |
| Dependencias externas | Ninguna | — | Stdlib puro — cero surface de ataque en la cadena de suministro de la propia herramienta |

### Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────┐
│                    Capa CLIENTE                      │
│              cmd/supply-radar (flag stdlib)           │
├─────────────────────────────────────────────────────┤
│                    Capa LÓGICA                       │
│  [scanner] → [parser (gomod/npm/pypi)]              │
│            → [vulnerability/osv] → [reporter]        │
│            → [cache/memory with TTL]                 │
├─────────────────────────────────────────────────────┤
│                   Capa DATOS                         │
│         File System (go.mod, package.json,           │
│         package-lock.json, go.sum, requirements.txt)  │
└─────────────────────────────────────────────────────┘
```

### Flujo de Datos

```
[Repo/Dir] → [Scanner orquesta] → [Parser por ecosistema (registry)] → [Dependency list]
  → [OSV BatchQuery (semáforo 10 goroutines + cache TTL)] → [Vulnerabilities]
  → [Reporter (tabla/JSON/markdown/SARIF)] → [stdout/archivo]
  → (--fail && vulns críticas) → exit code ≠ 0
```

---

## 📊 Matriz de Trazabilidad

| Req ID | Descripción | Componente | Estado | Verificación |
|--------|-------------|------------|--------|--------------|
| R-01 | Detectar dependencias Go (go.mod) | internal/parser/gomod/parser.go | ✅ | `go test ./internal/parser/gomod/` |
| R-02 | Detectar dependencias npm (package.json) | internal/parser/npm/parser.go | ✅ | `go test ./internal/parser/npm/` |
| R-03 | Consultar vulnerabilidades en OSV API | internal/vulnerability/osv | ✅ | Tests con mock de OSV |
| R-04 | Cache in-memory con TTL configurable | internal/cache/memory.go | ✅ | Test de TTL hit/miss |
| R-05 | Modo offline (sin red) | cmd/supply-radar | ✅ | Flag `--offline` |
| R-06 | Reporter tabla/JSON/json-summary/markdown | internal/reporter/{table,markdown} | ✅ | Tests por reporter |
| R-07 | Exit codes útiles para CI (`--fail`) | cmd/supply-radar | ✅ | Integración CI |
| R-08 | Parser package-lock.json (versiones exactas) | internal/parser/npm/lockfile.go | ✅ | lockfile_test.go |
| R-09 | Parser go.sum (versiones exactas + hashes) | internal/parser/gomod/go_sum.go | ✅ | go_sum_test.go |
| R-10 | Parser PyPI (requirements.txt) | internal/parser/pypi/parser.go | ✅ | parser_test.go |
| R-11 | Reporter SARIF (GitHub Code Scanning) | internal/reporter/sarif/reporter.go | ✅ | reporter_test.go |
| R-12 | SBOM export (SPDX, CycloneDX) | internal/reporter | ✅ | `go test ./internal/reporter/sbom/` |
| R-13 | Modo recursivo (monorepos) | internal/scanner | ✅ | `go test ./internal/scanner/ -run Recursive` |

---

## 🏗️ Marcos Conceptuales

### Software Supply Chain Security
La herramienta encarna el principio de "know what you depend on": el eslabón más débil de la cadena de suministro de software son las dependencias transitivas no revisadas. Escanear manifest + lockfile da visibilidad real (no lo declarado, sino lo materializado en el lockfile).

### Provider pattern extensible
La abstracción `Parser` (interfaz + registry) y `Provider` (interfaz + impl de OSV) permite añadir ecosistemas (PyPI, Maven) o proveedores de vulnerabilidades (NVD) sin tocar el core del scanner. La extensión es aditiva, no ruptura.

---

## ✅ Justificación de Decisiones Técnicas

| Decisión | Opción elegida | Alternativas evaluadas | Razón |
|----------|---------------|----------------------|-------|
| Lenguaje | Go 1.23 | Rust, Python | Single-binary distribuible; concurrencia nativa para paralelizar queries OSV; cero dependencias externas reduce el propio riesgo de supply chain |
| CLI framework | flag stdlib | Cobra, urfave/cli | El MVP tiene un solo comando; Cobra añade 200KB de binario y complejidad innecesaria. Flag stdlib basta. |
| Dependencias externas | Ninguna (stdlib puro) | go-semver, sarif-go | Una herramienta de supply chain security con dependencias propias es paradójica — stdlib puro minimiza la superficie de ataque de la herramienta misma |
| Cache | In-memory con TTL | Redis, archivo FS | El MVP no necesita persistencia cross-runs; cuando se necesite, un cache FS en internal/cache/ es incremental sin redesign |
| Concurrencia OSV | Semáforo de 10 goroutines | Worker pool ilimitado | Rate limit público de OSV es ~10 req/s sin auth; el semáforo respeta el límite sin backoff complejo |
| Parser por ecosistema | Implementación propia | library/go-mod, npm-parse | Sin libs externas; los manifests son texto estructurado, parsers propios son triviales y dan control total sobre edge cases |

---

## 📦 Estado de Implementación

### Fases Completadas

| Fase | Descripción | Commit | Verificación |
|------|-------------|--------|--------------|
| V1 | Parsers Go+npm, OSV, reporter tabla/JSON, cache TTL, modo offline, CI gate | cae5c13 | `go build ./...`, `go test ./...` verde; `go vet` limpio |
| V1.1 | package-lock.json, go.sum, markdown reporter, mensajes de progreso | 615fab4 | Tests por parser; CI 3-layer gates |

### Próximos Pasos (Backlog)

| ID | Descripción | Prioridad | Issue |
|----|-------------|-----------|-------|
| B-1 | SBOM export (SPDX, CycloneDX) | Alta | #1 |
| B-2 | Modo recursivo (monorepos) — ✅ | Alta | #1 |
| B-3 | Ecosistema Python (PyPI) y Rust (crates.io) | Media | #1 |
| B-4 | SARIF reporter (integración GitHub Code Scanning) — ✅ | Media | — |
| B-5 | Modo watch (CI monitor continuo) | Baja | — |
| B-6 | Cache filesystem persistente entre runs | Baja | — |
| B-7 | Portabilidad Windows vía PowerShell | Baja | — |

### Histórico de Versiones Recientes

- **v1.2.0 (2026-08-03)** — B-2 modo recursivo para monorepos completado: `filepath.WalkDir` con poda de directorios (`node_modules`, `vendor`, `.git`, etc.), detección multi-ecosistema (etiqueta `"multi"`), dedup por `ID@Path` preservando subproyectos. B-4 SARIF completado: schema URL migrada a `schemastore.org`, `invocations[]` con `startTimeUtc/endTimeUtc/executionSuccessful`, `automationDetails` con `category="supply-radar/scan"`, reglas `null` en caso vacío. Tests: 13 nuevos en `internal/scanner/recursive_test.go` + 3 nuevos en `internal/reporter/sarif/`.
- **v1.1.0 (2026-07-31)** — SBOM export SPDX 2.3 + CycloneDX 1.5 con info de vuln, package-lock.json y go.sum parsers, markdown reporter.

---

## ⚠️ Limitaciones Conocidas

1. Rate limit de OSV API (~10 req/s sin auth) — mitigado con semáforo, pero a 500+ deps puede ser cuello de botella (plan: mirror propio estilo GOPROXY)
2. Solo Linux/macOS x86_64 — Windows requiere PowerShell-only paths
3. No hay cache filesystem — cada run reconsulta OSV (in-memory solo dura la sesión del proceso)
4. El modo recursivo escala bien hasta ~1000 manifests; más allá de eso conviene paralelizar el_walk con un worker pool

---

## 🔐 Seguridad

- 100% local/offline-capable: no envía código fuente a servicios externos
- La herramienta misma no tiene dependencias externas (cero riesgo de supply chain en el scanner)
- Filtros por umbral de severidad para evitar ruido en CI
- Mapeo CVSS→severidad conservador para minimizar falsos positivos

---

## 📚 Referencias

- [OSV API — api.osv.dev](https://google.github.io/osv-scanner/)
- [SPDX Specification](https://spdx.dev/specifications/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [Sonatype State of the Software Supply Chain 2024](https://www.sonatype.com/state-of-the-software-supply-chain/)

---

*Generado por SophIA — Sebastian Velasco's autonomous operating system*
