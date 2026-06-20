# supply-radar — Requisitos

## 1. Historia de usuario (epics)

### Epic 1: Analisis Basico de Dependencias
Como desarrollador, quiero ejecutar una sola comando que me diga que dependencias tiene mi proyecto y si existen vulnerabilidades conocidas.

### Epic 2: Generacion de SBOM
Como ingeniero de seguridad, quiero generar un SBOM estandar de mi proyecto para auditorias de cumplimiento.

### Epic 3: Evaluacion de Riesgo
Como lider de equipo, quiero entender el riesgo agregado de mi supply chain en un reporte ejecutivo.

### Epic 4: Integracion CI/CD
Como devops engineer, quiero integrar el analisis en pipelines de CI para bloquear builds con vulnerabilidades criticas.

## 2. Requisitos Funcionales (MVP — V1.0)

| ID   | Requisito                                                      | Prioridad |
| ------- | ------------------------------------------------------------------ | ---------- |
| RF-01 | Detectar manifiesto de dependencias (go.mod, package.json, etc.).   | Must       |
| RF-02 | Extraer dependencias directas y transitivas del proyecto.       | Must       |
| RF-03 | Consultar vulnerabilidades para cada dependencia via OSV API.    | Must       |
| RF-04 | Generar reporte de vulnerabilidades con severidad (CVSS).       | Must       |
| RF-05 | Exportar SBOM en formato CycloneDX JSON.                        | Must       |
| RF-06 | Filtrar vulnerabilidades por severidad umbral (CRITICAL, HIGH).| Must       |
| RF-07 | Generar reporte ejecutivo: riesgo agregado, metricas clave.     | Must       |
| RF-08 | Soportar modo offline (sin consultas a API externa).           | Must       |
| RF-09 | Exportar reporte en formato JSON, tabla y CSV.                 | Should     |
| RF-10 | Configurar excepciones/suppressions para vulnerabilidades.     | Should     |

## 3. Requisitos No Funcionales

| ID    | Requisito                                                | Metrica objetivo                        |
| -------- | ------------------------------------------------------------ | ------------------------------------- |
| RNF-01 | Rendimiento: escanear proyectos pequenos en menos de 5s.  | <5s para <50 dependencias              |
| RNF-02 | Rendimiento: escanear proyectos grandes en menos de 30s.  | <30s para <5000 dependencias           |
| RNF-03 | Fiabilidad: manejar archivos de lock corruptos o incompletos. | Graceful degradation, no crash        |
| RNF-04 | Portabilidad: ejecutar en Linux, macOS y Windows.          | Builds nativos para las 3 plataformas   |
| RNF-05 | Tamanio: binario CLI < 50 MB.                               | <50 MB                                  |
| RNF-06 | Seguridad: nunca enviar codigo fuente a servicios externos. | Solo metadatos de dependencias        |
| RNF-07 | Usabilidad: CLI auto-explicativo con ayuda integrada.     | `--help` para todos los comandos        |
| RNF-08 | Testabilidad: cobertura de codigo > 80% en parsers y core. | >80% cobertura                         |
| RNF-09 | Extensibilidad: permitir anadir parseadores de nuevos lenguajes via plugin. | Interface bien definida               |
| RNF-10 | Mantenibilidad: documentacion en cada paquete publico (godoc).| 100% paquetes publicos documentados    |

## 4. Casos de uso principales

### UC-01: Escan rapido local
```bash
supply-radar scan .
# Muestra tabla de dependencias con vulnerabilidades
```

### UC-02: Validacion de pipeline CI
```bash
supply-radar scan . --severity-threshold CRITICAL --fail-on-vulnerabilities
# Exit code 1 si existen vulns CRITICAL, bloquea build
```

### UC-03: Generacion de SBOM para auditoria
```bash
supply-radar analyze . --format sbom --output bom.json
# Genera SBOM en formato CycloneDX
```

### UC-04: Reporte ejecutivo de riesgo
```bash
supply-radar analyze . --format report --output report.md
# Genera reporte markdown resumido para stakeholders
```
