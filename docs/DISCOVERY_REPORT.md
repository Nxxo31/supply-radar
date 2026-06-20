# Discovery Report — supply-radar

**Fecha:** 2025-01-15
**Autor:** Sebastian [Nxxo31]
**Estado:** Completado, listo para implementacion

---

## 1. Resumen Ejecutivo

Se completo la fase de discovery de supply-radar, definicion del MVP, arquitectura, requisitos y roadmap tecnico. El resultado es un blueprint completo para que el desarrollo fluya con determinacion.

---

## 2. Definicion del MVP

### Scope (V1.0)
- CLI escrito en Go detecta manifiestos Go y Node.js
- Extrae dependencias directas e indirectas
- Consulta vulnerabilidades via OSV API con caching
- Genera reportes en JSON y tabla
- Exporta SBOM basico en CycloneDX
- Modo offline con snapshot local
- Umbral de severidad y falla en CI

---

## 3. Arquitectura Propuesta

**Diseno:** Plugin-based CLI con 3 capas:
1. **Parsers** (detectan y parsean manifiestos por ecosistema)
2. **Analysis Engine** (consulta vulns, scoring, politicas)
3. **Reporters** (generan output en multiples formatos)

**Flujo de datos:**
```
Proyecto -> Detectores -> Parser -> Dependencias -> API OSV -> Cache -> Scoring -> Reporte
```

**Caches multi-level:**
- L1: sync.Map (memoria, hot)
- L2: SQLite (persistente, TTL configurable)
- L3: JSON offline snapshot

---

## 4. Riesgos Tecnicos Identificados

| Riesgo                           | Impacto | Mitigacion                                  |
| ---------------------------------- | ---------- | ------------------------------------------ |
| Parsing complejo de lockfiles     | Medio      | Usar go-dep-parser como base, tests exhaustivos |
| Desactualizacion de APIs externas | Alto       | Cache TTL, modo offline, sources configurables   |
| Falsos positivos                  | Medio      | Scoring mitigado, nota de confianza            |
| Latencia OSV API en scans grandes | Medio      | Parallelismo, cache agresiva, rate limiting   |
| Dependencias en terceros          | Medio      | Vendorizar cuando sea critico                |

---

## 5. Valor para el Portafolio

| Dimension                          | Contribucion del Proyecto                                          |
| ------------------------------------------ | --------------------------------------------------------- |
| Codigo Go aplicado a un problema real          | Parser multi-ecosistema, interfaces, estructuras de datos         |
| Diseno de CLI profesional                     | Cobra + Viper, flags, config, tests integrados                      |
| Integracion con APIs reales (OSV, NVD)        | HTTP clients, rate limiting, caching, retries                       |
| Testing en produccion                         | Unit + integration + benchmarks + CI/CD                             |
| Concepto open source de nivel producto       | README, CONTRIBUTING, issues, releases, comunidad                  |
| Documentacion tecnica arquitectural            | Diagramas, decisiones de diseno, ADRs                               |

---

## 6. Valor de Mercado

| Metrica                               | Valor                  |
| --------------------------------------- | ------------------------ |
| TAM Supply Chain Security                   | $2.9B (2025)           |
| Proyeccion 2034                              | $6.5B - $13.1B       |
| CAGR                                           | 9% - 18%               |
| Diferenciadores supply-radar                             | CLI multi-eco, open source, zero-config, Blob low  |
| Modelo futuro                                | Freemium CLI + SaaS dashboard (enterprise) |

---

## 7. Competidores Conceptuales

| Herramienta                  | Tipo          | Fortalezas                          | Debilidades (oportunidad)                       |
| -------------------------------- | --------------- | ---------------------------------- | --------------------------------------------------- |
| Snyk                             | SaaS         | Completo, integrado               | Patentado, costo, vendor lock-in                    |
| Trivy (Aqua)                   | CLI + SaaS    | Multi-eco, contenedores           | No Go-first, orientado a cloud                      |
| Grype (Anchore)                | CLI           | SBOM-first, SARIF                 | Orientado a containers, limitado sin Syft           |
| OWASP Dependency-Check        | CLI            | Gratis, maduro                    | Lento, dependencia de base de datos local grande    |
| OSV-Scanner (Google)           | CLI            | Simple, ecosystem agnostic        | Solo escaneo, sin scoring ni reportes               |
| **supply-radar**              | **CLI 1st**   | **Go-first, multi-eco, scoring**  | **Nuevo, validado con usuarios reales**             |

---

## 8. Recomendacion de Implementacion

### Paso 1: Setup de proyecto
```bash
# Estructura de un solo modulo Go
mkdir supply-radar && cd supply-radar
go mod init github.com/nxxo31/supply-radar
```

### Paso 2: Implementar en este orden
1. **cmd/** — Cobra CLI scaffolding
2. **internal/config** — Viper para config y flags
3. **internal/dependency/** — Tipos base
4. **internal/parser/** — Interface de parser + parser go.mod
5. **internal/parser/ npm** — parser package.json + lockfile
6. **internal/vulnerability/** — Client OSV API + cache
7. **internal/analyzer/** — Engine principal
8. **internal/reporter/** — JSON + table reporters
9. **tests/** — Integration tests con fixtures
10. **cmd/** — wiring final y release

### Paso 3: CI/CD pipeline
- GitHub Actions: test, lint (golangci-lint), build cross-platform
- Release: GoReleaser para binaries multi-plataforma
- Coverage: Codecov

### Paso 4: Validacion
- Benchmark: 50 deps < 5s, 5000 deps < 30s
- Test fixture proyectos: go (real), npm (real), Python (mock)
- Validacion con proyectos reales del usuario

---

## 9. Archivos Generados

- `/home/sebas/proyectos/supply-radar/PROJECT.md`
- `/home/sebas/proyectos/supply-radar/docs/ARCHITECTURE.md`
- `/home/sebas/proyectos/supply-radar/docs/REQUIREMENTS.md`
- `/home/sebas/proyectos/supply-radar/docs/TECHNICAL_DESIGN.md`

---

## 10. Recomendacion Estrategica

Iniciar implementacion inmediatamente. El MVP es claramente acotado y los bloqueos potenciales son conocidos y mitigables. Go es el lenguaje correcto. La arquitectura de plugins es la decision correcta para escala comunitaria. El mercado esta caliente para esta solucion.

### Proxima accion recomendada del operador:
1. Revisar documentos y aprobar / solicitar ajustes
2. Dar via verde para iniciar Fase ке (MVP Go + Node.js parser)
3. Definir primeras metricas de exito (tiempo de scan, tasa de adopcion)
