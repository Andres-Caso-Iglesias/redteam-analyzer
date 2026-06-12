# Vision General de la Arquitectura

Arquitectura tecnica de redteam-analyzer.

---

## Principios de Diseno

1. **Arquitectura basada en plugins** — Cada capacidad de escaneo es un plugin independiente. El motor central no conoce herramientas especificas.
2. **Protecciones legales en codigo** — La validacion de alcance, el rate limiting y el control de autenticacion se aplican a nivel del motor, no se añaden como elemento posterior.
3. **Defensa en profundidad** — Los fallos de plugins no crashean el escaneo. Cada plugin esta aislado y sus errores se capturan.
4. **Aislamiento de subprocess** — Las herramientas externas (nmap, nuclei, whatweb) se ejecutan como subprocess. Sin vinculaciones de biblioteca Python que puedan introducir conflictos de version.

---

## Arquitectura de Alto Nivel

```
CLI (Typer + Rich)
    |
    v
Motor (Engine)
    |
    +-- ScopeValidator    (rechaza objetivos fuera de alcance)
    +-- RateLimiter       (token bucket por dominio)
    +-- AuditLogger       (cada accion registrada)
    +-- PluginManager     (descubre y carga plugins)
    |
    v
Plugins (ejecucion secuencial)
    |
    +-- ReconPlugin   (crt.sh, DNS, VirusTotal, Shodan, WhatWeb, dirbust)
    +-- ScanPlugin    (nmap, masscan)
    +-- VulnPlugin    (emparejamiento CVE, plantillas Nuclei)
    +-- ReportPlugin  (generacion JSON, HTML, Markdown)
```

---

## Componentes Principales

### Motor (`src/redteam_analyzer/core/engine.py`)

El Engine es el unico punto de control. Orquesta todo el pipeline de escaneo:

1. Valida el alcance del objetivo antes de cualquier llamada de red
2. Filtra modulos segun la disponibilidad de autenticacion
3. Ejecuta plugins secuencialmente via `PluginManager`
4. Fusiona resultados de todos los plugins en un solo `ScanResult`
5. Registra cada accion en el registro de auditoria
6. Maneja fallos de plugins gracefully (un plugin que falla no detiene a los demás)

### PluginManager (`src/redteam_analyzer/core/plugin_manager.py`)

Responsable de descubrir, cargar y gestionar plugins:

- Descubre plugins escaneando `src/redteam_analyzer/modules/` en busca de subclases de `BasePlugin`
- Busca tanto atributos a nivel de paquete como submodulos (maneja `__init__.py` vacios)
- Cachea instancias de plugins cargados
- Valida dependencias de plugins antes de la ejecucion

### ScopeValidator (`src/redteam_analyzer/core/scope.py`)

Aplica restricciones de alcance de objetivos:

- Valida IPs contra rangos CIDR
- Valida dominios contra patrones permitidos (incluyendo wildcards)
- Valida URLs contra hosts permitidos
- Eleva `ScopeError` para objetivos fuera de alcance — esta excepcion es capturada por el Engine y registrada

### RateLimiter (`src/redteam_analyzer/utils/rate_limiter.py`)

Previene la denegacion de servicio accidental:

- Algoritmo de token bucket con capacidad y tasa de relleno configurables
- Buckets por dominio (cada dominio tiene su propio limite de tasa)
- Bucket global (limite general a traves de todos los dominios)
- Compatible con asyncio usando `asyncio.sleep` para esperas no bloqueantes

### AuditLogger (`src/redteam_analyzer/utils/audit_log.py`)

Mantiene un registro completo de auditoria:

- Cada accion (inicio de escaneo, inicio/fin de plugin, errores) se registra
- Las entradas incluyen marca de tiempo, objetivo, modulo, accion, estado de exito/fallo y detalles de error
- Se persiste en `audit_log.json` al completar el escaneo
- Consultable por objetivo y modulo para analisis post-escaneo

---

## Arquitectura de Plugins

### BasePlugin (`src/redteam_analyzer/modules/base.py`)

Clase base abstracta que todos los plugins deben implementar:

```python
class BasePlugin(ABC):
    name: str
    description: str

    @abstractmethod
    async def run(self, target: Target, config: ScanConfig) -> ScanResult:

    @abstractmethod
    def validate_dependencies(self) -> List[ToolInfo]:
```

### Ciclo de Vida de un Plugin

1. **Descubrimiento** — PluginManager escanea paquetes de modulos en busca de subclases de `BasePlugin`
2. **Carga** — Se crea la instancia del plugin y se cachea
3. **Verificacion de dependencias** — `validate_dependencies()` verifica que las herramientas requeridas esten instaladas
4. **Ejecucion** — Se llama a `run()` con el objetivo y la configuracion acumulada
5. **Fusion de resultados** — El `ScanResult` del plugin se fusiona en el resultado acumulado

### Aislamiento de Plugins

Cada plugin se ejecuta en un bloque try/except dentro del Engine. Si un plugin eleva una excepcion:

- El error se registra en el registro de auditoria
- El mensaje de error se agrega a `ScanResult.errors`
- El Engine continua con el siguiente plugin

Esto significa que un escaneo de Nuclei que falla no impide la generacion de reportes con resultados parciales.

---

## Modelos de Datos (`src/redteam_analyzer/core/models.py`)

Todos los modelos de datos usan Pydantic v2 para validacion y serializacion:

| Modelo | Proposito |
|--------|-----------|
| `Target` | Representa un objetivo de escaneo (IP, hostname, URL) |
| `Finding` | Un hallazgo individual de vulnerabilidad o informacion |
| `ScanResult` | Resultados acumulados de la ejecucion de plugins |
| `ScanConfig` | Configuracion completa del escaneo |
| `ScopeConfig` | Restricciones de alcance del objetivo |
| `ScanMetadata` | Metadatos de ejecucion del plugin (duracion, marca de tiempo) |
| `ToolInfo` | Informacion de disponibilidad de herramientas externas |

---

## Integracion con Herramientas Externas

Todas las herramientas externas se ejecutan como subprocess via `run_tool()` en `src/redteam_analyzer/utils/external_tools.py`:

- **stdout** se captura y parsea (XML para nmap, JSONL para nuclei)
- **stderr** se envia opcionalmente a un callback de progreso (maneja terminadores de linea `\n` y `\r`)
- **Timeouts** se aplican por herramienta con limites configurables
- **Errores** se envuelven en `ToolNotFoundError` o `ToolTimeoutError`

### Por que subprocess y no bibliotecas Python?

- Aislamiento de version: las vinculaciones Python de nmap entran en conflicto con el nmap del sistema
- Seguridad: los subprocess estan naturalmente sandboxed
- Confiabilidad: las herramientas instaladas en el sistema son mantenidas por el SO
- Flexibilidad: se puede cambiar nmap por masscan sin cambios de codigo

---

## Estructura de Tests

```
tests/
├── test_core/          # Tests unitarios para motor, modelos, alcance
├── test_modules/       # Tests unitarios para cada plugin
├── test_cli/           # Tests de integracion del CLI
├── test_utils/         # Tests unitarios para rate limiter, audit log
└── e2e/                # Tests de integracion end-to-end
```

- **135 tests** todos pasando
- Usa `pytest-asyncio` con `asyncio_mode=auto`
- Los tests E2E ejecutan el pipeline completo con herramientas externas mockeadas
- Los tests unitarios mockean en la frontera del subprocess

---

## Stack Tecnologico

| Componente | Tecnologia |
|------------|------------|
| Framework CLI | Typer |
| Salida terminal | Rich |
| Modelos de datos | Pydantic v2 |
| Cliente HTTP | httpx |
| Formato de config | YAML (PyYAML) |
| Plantillas | Jinja2 |
| Testing | pytest, pytest-asyncio |
| Verificacion de tipos | mypy |
| Linting | ruff |
| Gestion de paquetes | setuptools |
