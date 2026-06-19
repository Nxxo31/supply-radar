# Supply Radar

## Status & Sprint
- **Status**: Inicialización (sin implementación funcional)
- **Sprint goal**: Crear estructura base y formalizar el proyecto para desarrollo futuro

## Problema
Los ataques a la cadena de suministro de software (paquetes npm/PyPI comprometidos) crecieron drásticamente. Las herramientas de SCA existentes (Dependabot) avisan de CVEs conocidos pero no de dependencias "muertas" (sin mantenimiento) o con patrones de riesgo (cambio reciente de mantenedor, ofuscación de código).

## Mercado
Equipos de seguridad de aplicaciones (AppSec), empresas con requisitos de compliance (SBOM obligatorio en gobierno/finanzas), mantenedores de proyectos open source.

## Valor profesional
Demuestra conocimiento de seguridad de software, generación/parsing de SBOM (estándar real de la industria), y diseño de un sistema de scoring de riesgo.

## Diferenciación
Va más allá de "buscar CVEs en una base de datos": calcula un score de riesgo compuesto (mantenimiento, popularidad, cambios de propiedad, señales de comportamiento sospechoso en releases) — más cercano a lo que hacen herramientas comerciales caras (Socket.dev, Snyk) pero open source y explicable.

## Modelo de negocio
CLI/Action open source gratuita; SaaS de pago para monitoreo continuo de organizaciones con múltiples repos y reportes de compliance (SBOM firmado). **Sin tecnologías de pago en el stack**.

## Stack recomendado
- **Lenguaje:** Go (rendimiento al escanear árboles de dependencias grandes, binario único fácil de distribuir). Sin costo.
- **Framework:** CLI propia; integración con estándar CycloneDX/SPDX para SBOM. Sin costo.
- **Base de datos:** Postgres para la versión SaaS (histórico de scores); el CLI core es stateless. Sin costo en MVP.
- **Cloud:** Distribución como binario + GitHub Action; SaaS en cualquier proveedor de contenedores. Sin costo en MVP.
- **APIs:** Consultas a registries públicos (npm, PyPI, crates.io) y bases de CVE (OSV.dev). Sin costo.
- **Infraestructura:** Cache local de resultados para evitar rate-limiting en registries. Sin costo.
- **Testing:** Fixtures con dependencias conocidas maliciosas/benignas (casos históricos documentados) para validar el scoring. Sin costo.
- **Seguridad:** Verificación de firmas/checksums de paquetes cuando estén disponibles.

## Requisitos funcionales
- Generar SBOM estándar (CycloneDX) a partir del lockfile del proyecto.
- Calcular score de riesgo por dependencia (mantenimiento, popularidad, antigüedad, cambios de mantenedor).
- Detectar dependencias "muertas" (sin commits en X meses) y huérfanas (sin mantenedor activo).
- Reporte priorizado de remediación (qué reemplazar primero).
- Integración en CI con umbral de fallo configurable.

## Requisitos no funcionales
- Escaneo de un proyecto con 1,000+ dependencias en menos de 30 segundos (con cache).
- Funcionamiento sin enviar el código fuente del usuario a servidores externos (solo metadata de dependencias).
- Actualización de fuentes de datos de riesgo al menos semanal.

## Arquitectura
CLI que parsea el lockfile, construye el grafo de dependencias, consulta en paralelo (con cache y rate-limiting) los registries y bases de vulnerabilidades, aplica el motor de scoring (ponderación configurable de señales) y genera el SBOM + reporte. La versión SaaS añade un scheduler que re-ejecuta el escaneo periódicamente y almacena histórico para detectar degradación de riesgo a lo largo del tiempo.

## MVP
Soporte solo para npm, cálculo de un score simple (antigüedad + popularidad + CVEs conocidos), salida en terminal.

## Roadmap
- **V1:** npm + scoring básico + SBOM CycloneDX.
- **V2:** PyPI/crates.io, detección de dependencias muertas, GitHub Action.
- **V3:** SaaS con histórico, alertas de cambio de mantenedor, firma de SBOM.

## Complejidad
Media-Alta

## Tiempo estimado
2-3 semanas

## Impacto GitHub
8/10

## Valor empleabilidad
8/10
