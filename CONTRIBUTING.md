# Contribuir a supply-radar

¡Gracias por tu interés en mejorar `supply-radar`! Este proyecto es un CLI open source para análisis de dependencias y detección de riesgos de software supply chain, escrito en Go.

## Antes de empezar

- Abre un **issue** describiendo el problema o la mejora que propones. Si es un bug, incluye los pasos para reproducirlo y el output de `supply-radar -version`.
- Para features grandes, espera confirmación en el issue antes de empezar a codear.

## Configuración local

```bash
git clone https://github.com/Nxxo31/supply-radar.git
cd supply-radar
go build -o supply-radar .
go test ./...
```

Requisitos: **Go 1.23+**.

## Reglas del proyecto

- **No commitear binarios** (`supply-radar`, `supply-radar-bin`). Están excluidos del repo.
- Ejecuta `go vet ./...` antes de cada commit.
- Un commit por cambio — atómico y enfocado.
- Mensajes de commit **en español**, prefijados por tipo (`feat:`, `fix:`, `chore:`, `docs:`).

## Flujo de trabajo

1. Crea una rama desde `main`: `git checkout -b feat/mi-mejora`.
2. Implementa el cambio. Estados intermedios aceptables si tests pasan.
3. Verifica: `go build && go test ./... && go vet ./...`.
4. Commitea en español: `git commit -m "feat: añade soporte para pyproject.toml"`.
5. Abre un Pull Request a `main` con una descripción clara del qué y el porqué.

## Estilo de código

- Sigue [`gofmt`](https://pkg.go.dev/cmd/gofmt) y `golint`.
- Manejo de errores explícito — nunca `panic` en producción.
- Tests en `tests/` o junto al paquete. Cobrajetivos: cubrir el path normal y el path de error.

## Reportes y nuevos ecosistemas

Para añadir un nuevo ecosistema (PyPI, Cargo, Maven…):

1. Implementa un parser en `internal/`.
2. Añade tests con manifiestos de ejemplo.
3. Documenta el formato soportado en `docs/`.
4. Actualiza la lista de ecosistemas del `README.md`.

## Reporte de vulnerabilidades

Si encuentras una vulnerabilidad en el propio `supply-radar`, **no abras un issue público**. Escribe a través de GitHub Security Advisories o contacta directamente al mantenedor.

## Licence

Al contribuir aceptas que tus cambios se publican bajo la **licencia MIT** del proyecto.

---

_Fork, diverge, mejora — toda contribución bienvenida._
