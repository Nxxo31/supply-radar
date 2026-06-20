# supply-radar — Arquitectura

## Vision de Arquitectura

supply-radar sigue un diseno **modular de plugins** con tres capas principales:

1. **Entrada:** Parsers de manifiesto por ecosistema
2. **Procesamiento:** Motor de analisis, consulta a APIs de vulnerabilidades, scoring
3. **Salida:** Generadores de reporte multi-formato

## Diagrama de Contexto (C4 Level 1)

```mermaid
graph TB
    subgraph User
        Dev[Desarrollador / DevOps]
    end
    subgraph supply-radar
        CLI[CLI Tool]
    end
    subgraph External
        OSV[OSV API]
        NVD[NVD/CVE API]
        GH[GitHub API]
    end
    Dev --> CLI
    CLI --> OSV
    CLI --> NVD
    CLI --> GH
```

## Diagrama de Componentes (C4 Level 2)

```mermaid
graph TB
    subgraph CLI
        cmd[Cmd Layer<br/>Cobra]
        config[Config<br/>Viper]
    end
    subgraph Core
        engine[Analysis Engine]
        cache[Cache Layer]
        rules[Rules Engine]
    end
    subgraph Input[Parsers]
        go_parser[Go Parser]
        js_parser[JS/TS Parser]
        py_parser[Python Parser]
        rb_parser[Ruby Parser]
        cargo_parser[Rust Parser]
    end
    subgraph Output[Reporters]
        json_rep[JSON Reporter]
        sarif_rep[SARIF Reporter]
        md_rep[Markdown Reporter]
        cyclone_rep[CycloneDX Reporter]
    end
    subgraph External
        osv[OSV API]
        nvd[NVD Feed]
    end

    cmd --> engine
    cmd --> config
    engine --> cache
    engine --> rules
    engine --> go_parser
    engine --> js_parser
    engine --> py_parser
    engine --> rb_parser
    engine --> cargo_parser
    engine --> json_rep
    engine --> sarif_rep
    engine --> md_rep
    engine --> cyclone_rep
    engine --> osv
    engine --> nvd
```

## Diagrama de Flujo de Analisis

```mermaid
sequenceDiagram
    participant U as Usuario
    participant CLI as supply-radar
    participant P as Parser
    participant E as AnalysisEngine
    participant C as Cache
    participant OSV as OSV API
    participant R as Reporter

    U->>CLI: supply-radar scan .
    CLI->>P: detectManifests(path)
    P-->>CLI: []Dependency
    CLI->>E: analyze(dependencies)
    loop Por cada dependencia
        E->>C: getCachedVulns(dep)
        alt Cache miss
            C-->>E: nil
            E->>OSV: query(dep.name, dep.version)
            OSV-->>E: []Vulnerability
            E->>C: cache(dep, vulns)
        else Cache hit
            C-->>E: []Vulnerability
        end
        E->>E: calculateRiskScore()
        E->>E: applyPolicy()
    end
    E-->>CLI: AnalysisResult
    CLI->>R: generate(AnalysisResult, format)
    R-->>CLI: Reporte
    CLI-->>U: Reporte + exitCode
```

## Diagrama de Modelo de Datos

```mermaid
erDiagram
    PROJECT ||--o{ DEPENDENCY : contains
    DEPENDENCY ||--o{ VULNERABILITY : has
    PROJECT ||--o{ SBOM : generates
    DEPENDENCY ||--o{ DEPENDENCY : "depends on"
    VULNERABILITY ||--o{ CVSS : scored_by

    PROJECT {
        string name
        string path
        string version
        datetime scan_time
        string tool_version
    }

    DEPENDENCY {
        string id PK
        string name
        string version
        string ecosystem
        string path
        bool direct
        string license
        string repository_url
        datetime last_updated
    }

    VULNERABILITY {
        string id PK
        string cve_id
        string title
        string description
        string severity
        float cvss_score
        datetime published
        datetime modified
        bool fixed
    }

    CVSS {
        string id PK
        float score
        string vector
        string version
    }

    FINDING {
        string id PK
        string dep_id FK
        string vuln_id FK
        string severity
        bool suppressed
    }

    SBOM {
        string id PK
        string format
        string version
        string content
        datetime generated_at
    }
```

## Paquetes del Dominio

```
internal/
  analyzer/       Motor de analisis principal
  cache/          Cache local de vulnerabilidades
  config/         Configuracion y settings
  dependency/     Entidades y repositorios de dependencias
  parser/         Interfaces y registros de parsers
  reporter/       Interfaces y registros de reporters
  rules/          Reglas de politicas de riesgo
  scanner/        Orquestador del flujo de escaneo
  vulnerability/  Consultas a APIs de vulnerabilidades
```

## Proveedores de Parser

| Ecosistema | Manifiesto                     | Archivo Lock              | Complejidad |
| ----------------- | -------------------------------- | -------------------------- | --------------- |
| Go                | go.mod                              | go.sum                          | Baja          |
| Node.js           | package.json                        | package-lock.json / yarn.lock / pnpm-lock.yaml | Media         |
| Python            | pyproject.toml / setup.py           | poetry.lock / Pipfile.lock / requirements.txt | Media         |
| Ruby              | Gemfile                             | Gemfile.lock                    | Baja          |
| Rust              | Cargo.toml                          | Cargo.lock                      | Baja          |
| Java              | pom.xml / build.gradle              | gradle.lockfile                 | Media         |
| .NET              | .csproj / .fsproj                   | packages.lock.json              | Media         |

## Cache y Almacenamiento

- **Cache local:** SQLite para persistencia de resultados de escaneos previos
- **Cache de vulnerabilidades:** TTL de 24 horas por defecto (configurable)
- **Tamanio estimado:** ~100 MB para 10k dependencias con historial completo

## Roadmap Tecnico

### Fase ке (MVP)
- Parser Go (go.mod + go.sum)
- Parser Node.js (package.json + package-lock.json)
- Consulta a OSV API
- Reporte JSON + Tabla
- Configuracion basica

### Fase 2 (V1.1)
- Parsers Python, Ruby
- Cache SQLite con TTL
- Reporte SARIF
- Umbral de severidad
- Configuracion por archivo (.supply-radar.yaml)

### Fase 3 (V1.2)
- Parsers Rust, Java, .NET
- Generacion SBOM CycloneDX
- Modo offline completo
- Excepciones/suppressions
- Plugin system basico

### Fase 4 (V2.0)
- Reporte ejecutivo con dashboards
- Integracion GitHub Actions / GitLab CI
- Soporte multi-lenguaje en un solo scan
- CLI interactiva (TUI)
