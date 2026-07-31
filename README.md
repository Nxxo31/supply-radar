# supply-radar

[![CI](https://github.com/Nxxo31/supply-radar/actions/workflows/ci.yml/badge.svg)](https://github.com/Nxxo31/supply-radar/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OSV Database](https://img.shields.io/badge/Vulns-OSV.dev-red)](https://osv.dev)

> CLI open source para análisis de dependencias y detección de riesgos de software supply chain.

`supply-radar` escanea proyectos Go y Node.js, analiza sus archivos de manifiesto, consulta la [base de datos OSV](https://osv.dev) en busca de vulnerabilidades conocidas y produce un reporte claro y ejecutable en segundos.

Sin SaaS. Sin dashboards. Sin base de datos. Sin envío de dependencias a servidores externos.

---

## Diagrama del Scanner

```
 ┌─────────────────────────────────────────────────────────────┐
 │                    supply-radar CLI                          │
 │                                                              │
 │  ┌──────────┐    ┌──────────┐    ┌───────────────────────┐  │
 │  │ Manifest │───▶│  Parser  │───▶│   Dependency List     │  │
 │  │ Files    │    │ Registry │    │  (direct + transitive) │  │
 │  └──────────┘    └──────────┘    └───────────┬───────────┘  │
 │       ▲                                     │              │
 │  go.mod / package.json                      ▼              │
 │  requirements.txt    ┌──────────────────────────────────┐   │
 │                      │     Vulnerability Provider      │   │
 │                      │         (OSV API)                │   │
 │                      │   ┌────────────────────────┐    │   │
 │                      │   │  In-Memory Cache (TTL) │    │   │
 │                      │   └────────────────────────┘    │   │
 │                      └───────────────┬──────────────────┘   │
 │                                      │                      │
 │                                      ▼                      │
 │                      ┌──────────────────────────────────┐   │
 │                      │          Reporter                │   │
 │                      │  table │ json │ sarif │ markdown │   │
 │                      └──────────────────────────────────┘   │
 └─────────────────────────────────────────────────────────────┘
```

---

## Por qué

La crisis de la cadena de suministro de software es real:

- **+67%** de dependencias no revisadas en 2024-2025 (Sonatype).
- Ataques a supply chain crecieron exponencialmente post-Log4j (2021) y XZ backdoor (2024).
- Vulnerabilidades criticas tardan **500+ dias** en resolverse.
- Equipos carecen de visibilidad de que hay realmente en su proyecto.

`supply-radar` responde las preguntas basicas que un desarrollador necesita responder hoy:

1. Que dependencias usa realmente mi proyecto? (directas y transitivas)
2. Hay vulnerabilidades conocidas para esas versiones?
3. Cual es el nivel de riesgo agregado?
4. En que version se parcheo cada problema?

---

## Instalacion

### Desde el codigo fuente

```bash
git clone https://github.com/Nxxo31/supply-radar.git
cd supply-radar
go build -o supply-radar .
./supply-radar --version
```

**Requisitos:** Go 1.23+

### Instalacion con `go install`

```bash
go install github.com/nxxo31/supply-radar@latest
```

### Verificacion

```bash
supply-radar --version
# supply-radar v0.1.0
```

---

## Uso

```bash
# Escanear el directorio actual (detecta automaticamente Go o Node.js)
supply-radar .

# Escanear un proyecto especifico en formato tabla
supply-radar ./mi-proyecto

# Reporte en JSON para integracion con CI/CD
supply-radar --format json --output report.json ./mi-proyecto

# Solo vulnerabilidades criticas (util para CI gates)
supply-radar --threshold CRITICAL ./mi-proyecto

# Falla si se encuentra cualquier vulnerabilidad
supply-radar --fail ./mi-proyecto

# Modo offline (usa solo cache, sin llamadas de red)
supply-radar --offline ./mi-proyecto

# Resumen compacto en JSON para CI gates rapidos
supply-radar --format json-summary ./mi-proyecto

# Reporte SARIF para GitHub Code Scanning
supply-radar --format sarif --output results.sarif ./mi-proyecto

# Markdown para documentacion o issues
supply-radar --format markdown --output SECURITY.md ./mi-proyecto
```

### Flags

| Flag | Descripcion | Default |
|------|-------------|---------|
| `--path` | Ruta del proyecto | `.` |
| `--format` | `table` \| `json` \| `json-summary` \| `markdown` \| `sarif` | `table` |
| `--output` | Archivo de salida o `-` para stdout | `-` |
| `--threshold` | `CRITICAL` \| `HIGH` \| `MEDIUM` \| `LOW` | — |
| `--fail` | Sale con codigo 1 si hay vulnerabilidades | `false` |
| `--offline` | Solo datos cacheados, sin red | `false` |
| `--cache-ttl-hours` | TTL del cache en horas | `24` |
| `--version` | Imprime version y sale | — |
| `--help` | Muestra ayuda | — |

---

## Ecosistemas soportados

| Ecosistema | Archivos de manifiesto |
|------------|----------------------|
| **Go** | `go.mod`, `go.sum` |
| **npm** | `package.json`, `package-lock.json` |
| **PyPI** | `requirements.txt`, `pyproject.toml` |

---

## Variables de entorno

| Variable | Descripcion |
|----------|-------------|
| `SUPPLY_RADAR_FORMAT` | Formato de salida (igual que `--format`) |
| `SUPPLY_RADAR_OUTPUT` | Archivo de salida (igual que `--output`) |
| `SUPPLY_RADAR_THRESHOLD` | Filtro de severidad |
| `SUPPLY_RADAR_FAIL_ON_VULNS` | `true` para activar `--fail` |
| `SUPPLY_RADAR_OFFLINE` | `true` para activar `--offline` |

---

## Ejemplo de integración con GitHub Actions

See [docs/examples/github-actions-sarif.yml](docs/examples/github-actions-sarif.yml) for a complete GitHub Actions workflow that runs supply-radar and uploads results to GitHub Code Scanning using the SARIF format.

---

## Ejemplo de salida (tabla)

```bash
supply-radar ./tests/fixtures/node/express-app
```

```
 -- supply-radar v0.1.0 ---
 Project:  express-app
 Duration: 2121ms
 ---

  Found 29 vulnerabilities in 4 dependencies -- CRITICAL issues require immediate action
   CRITICAL: 1  |  HIGH: 12  |  MEDIUM: 14  |  LOW: 2
   Risk Score: 10.0/10

 Vulnerable Dependencies:
 PACKAGE              SEVERITY   CVSS
 minimist             CRITICAL
   GHSA-xvch-5gv4-984h
 axios                HIGH
   21 vulnerabilities
 lodash               HIGH
   5 vulnerabilities
 express              MEDIUM
   2 vulnerabilities
```

---

## Como funciona

1. **Deteccion**: busca `go.mod` o `package.json` en la ruta indicada.
2. **Parsing**: extrae dependencias (directas e indirectas) con cero deps externas.
3. **Consultas OSV**: cada dependencia se consulta en `api.osv.dev/v1/query` en paralelo.
4. **Cache**: respuestas de OSV se cachean en memoria (TTL configurable).
5. **Reporte**: se calcula score de riesgo y se serializa en el formato elegido.

No se envian dependencias a servidores externos: solo se hacen POSTs a `api.osv.dev`
con package y version. En modo `--offline` no se hace ninguna llamada de red.

---

## Arquitectura

```
cmd/supply-radar/         CLI entry point + flags
  internal/
    scanner/              Orquestador: parser -> vulns -> report
    parser/               Interfaces + registry
      gomod/              Parsea go.mod
      npm/                Parsea package.json
    vulnerability/        Contrato Provider
      osv/                Cliente OSV (HTTP + parsing)
    reporter/             Reporters
      table/              Terminal output
    dependency/           Tipos del dominio
    cache/                Cache in-memory con TTL
    config/               Env vars
```

Cada paquete tiene una responsabilidad unica y se puede extender sin tocar el resto.

### Anadir un ecosistema nuevo

1. Crear `internal/parser/mi-ecosistema/parser.go` implementando `parser.Parser`.
2. Registrarlo en `internal/scanner/scanner.go`.
3. Si el ecosistema tiene un equivalente OSV (pypi, maven, crates.io), solo
   hay que mapear el ecosystem en `internal/vulnerability/osv/client.go`.

El resto del pipeline (cache, reporter, exit codes) funciona sin cambios.

---

## Roadmap

| Version | Features |
|---------|----------|
| **V1 (actual)** | Scan, OSV queries, reporte tabla/JSON, CI flag |
| V1.1 | Soporte `package-lock.json` y `go.sum` para versiones exactas |
| V1.2 | SBOM export en formatos SPDX y CycloneDX |
| V2.0 | Mas proveedores de vulns (NVD, GHSA directo), paquete PyPI/Maven |

Ver [PROJECT.md](PROJECT.md) para la vision completa.

---

## Contribuir

PRs bienvenidos. Antes de abrir uno:

1. Asegurate de que `go test ./...` pase.
2. Añade tests para cualquier logica nueva.
3. `gofmt -d .` no debe reportar diferencias.
4. Manten el MVP simple: nada de SaaS, dashboards, o DBs externas.

---

## Licencia

MIT. Ver [LICENSE](LICENSE).

---

## Autor

Sebastian [Nxxo31] - proyecto de ingenieria open source.
