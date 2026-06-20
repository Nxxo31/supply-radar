# supply-radar

Supply Chain Security Analysis CLI Tool

## Status

MVP V1 funcional. Detecta dependencias Go (go.mod) y npm (package.json), consulta
vulnerabilidades en OSV, reporta en tabla/JSON/json-summary. Tests y CI en verde.

## Sprint activo

V1.1: soporte lockfiles (package-lock.json y go.sum) y feedback de progreso.

## Vision

supply-radar es una herramienta CLI open source para analisis de dependencias y
riesgos de software supply chain. Escanea repositorios, detecta componentes
vulnerables, genera SBOMs (futuro), y produce reportes de riesgo ejecutables
sin friccion.

## Problema

### La crisis de la cadena de suministro de software

- En 2024-2025: dependencias no revisadas aumentaron 67% (Sonatype).
- 0 paquetes nuevos son revisados antes de entrar a la cadena.
- Ataques a supply chain crecieron exponencialmente post-Log4j (2021) y XZ backdoor (2024).
- Vulnerabilidades criticas tardan 500+ dias en resolveerse.
- Equipos carecen de visibilidad de que tienen en sus proyectos.

### Dolores concretos de desarrolladores

1. No saben que dependencias usa realmente su proyecto.
2. No saben que vulnerabilidades existen hoy.
3. No saben que licencias implica cada componente.
4. No saben si un paquete es mantenido activamente.
5. No saben si existe un maintainer unico que puede ser comprometido.

## Oportunidad

El mercado de Supply Chain Security valdra $6.5B+ en 2034 (CAGR 9-18%). Demanda
creciente de soluciones abiertas, autonomas y faciles de integrar en CI/CD.

## MVP V1 (ENTREGADO)

Funcionalidad ya operativa:

- Dos ecosystems: Go (go.mod) y npm (package.json).
- Versionado de dependencias con limpieza de prefijos (v, ^, ~).
- Deteccion de directas vs indirectas.
- Consultas a OSV API con cache in-memory y TTL configurable.
- Modo offline (sin red).
- Reportes en tres formatos: tabla, JSON, json-summary.
- CLI con flags y validacion.
- Exit codes utiles para CI (--fail cuando hay vulns).
- Filtro por umbral de severidad.
- Tests unitarios en verde (parser, scanner, OSV client, table reporter).
- CI workflow en GitHub Actions.

## Definition of Done para el MVP

- go build ./... sin errores.
- go test ./... sin errores.
- go vet ./... sin warnings.
- gofmt limpio.
- Escaneo de un proyecto real detecta vulnerabilidades reales.
- CI pasa en push/PR.

## Stack

- Lenguaje: Go 1.23+.
- Dependencias externas: ninguna (stdlib puro).
- CLI: flag stdlib (Cobra era overkill para MVP).
- Parsers: implementacion propia, sin librerias externas.
- HTTP: net/http stdlib para OSV.
- Tests: testing stdlib.

## Arquitectura de paquetes

  cmd/supply-radar/        Entrada del binario + logica de flags
    internal/
      scanner/             Orquesta el pipeline completo
      parser/              Interfaz Parser + registry
        gomod/             Parser de go.mod (require, indirect, inline syntax)
        npm/               Parser de package.json (deps + devDeps)
      vulnerability/       Interfaz Provider
        osv/               Cliente HTTP a api.osv.dev
      reporter/            Interfaz Reporter
        table/             Tabla ASCII con summary
      dependency/          Tipos del dominio
      cache/               Cache in-memory + TTL
      config/              Env vars (placeholder, main.go es la verdad actual)

Decisiones de arquitectura:

- Sin ORM, sin DB, sin HTTP server. Es solo un binario que lee y reporta.
- Cache en proceso: el MVP no necesita persistencia cross-runs. Cuando se
  necesite, se puede anadir un cache filesystem en internal/cache/.
- Paralelismo controlado: OSV BatchQuery usa semaforo de 10 goroutines.
  Suficiente para el rate limit publico de api.osv.dev.

## Roadmap

### V1 (actual, completado)

- Parsers Go y npm.
- OSV provider.
- Reporter tabla/JSON.
- Cache TTL.
- Modo offline.
- CI gate flag.

### V1.1 (siguiente sprint)

- Parser de package-lock.json (versiones exactas).
- Parser de go.sum (versiones exactas, manejo de hashes).
- Mensajes de progreso durante scan.
- Markdown reporter.

### V1.2

- SBOM export: SPDX.
- SBOM export: CycloneDX.
- Modo recursivo (monorepos).

### V2.0

- Ecosistema Python (PyPI) y Rust (crates.io).
- SARIF reporter (integracion nativa con GitHub Code Scanning).
- Modo watch (CI monitor continuo).
- Cache filesystem persistente entre runs.

## Roadmap tecnico no funcional

- performance: V1 escanea <50 deps en <3s. Si proyectamos 500 deps, evaluar pipeline streaming.
- concurrency: rate limit OSV es ~10 req/s sin auth. Plan B: GOPROXY style mirror propio.
- portability: solo Linux/macOS x86_64 por ahora. Windows via PowerShell.
- observability: logs a stderr, metricas no necesarias en V1.

## Riesgos tecnicos identificados

  Riesgo                                Impacto   Mitigacion
  ------------------------------------- -------   ----------------------------------------------
  Rate limit de OSV API                 Medio     Semaforo de 10 goroutines, cache TTL
  Parsing parcial de lockfiles grandes  Medio     Stream-based parser para V1.1, no full in-memory
  Falsos positivos                      Bajo      Mapeo CVSS->severidad conservador, threshold filter
  Cambios en esquema OSV API            Bajo      Validacion en parsing, fallback a "UNKNOWN"

## Valor de portafolio

1. Demostracion de arquitectura Go moderna (CLI + parsers + reporting).
2. Interfaces de parsing extensibles (futuro PyPI/Maven sin tocar el core).
3. Integracion con OSV (estandar de la industria).
4. Diseno orientado a providers (cambiar de OSV a NVD es trivial).
5. CLI product-ready con manejo de errores, tests y CI.

## Valor de mercado

  Aspecto                          Valoracion
  --------------------------------- ---------------------------------------------
  TAM Mercado SCA                   $2.9B en 2025, $6.5B proyectado 2034
  Tendencia                         Crecimiento del 9-18% CAGR
  Diferenciador supply-radar        CLI ligero, multi-ecosistema desde V1, autonomo, OSS
  Posicionamiento                   Herramienta de desarrollador para CI/CD integrado
  Modelo de revenue potencial       Soporte enterprise + SaaS (futuro, NO MVP)
  Traccion esperada                 Estrellas GitHub, integracion con GitHub Actions

## Licencia

MIT. Ver LICENSE.
