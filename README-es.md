# redteam-analyzer

Herramienta CLI para analisis de seguridad de red team -- reconocimiento, escaneo de puertos, deteccion de vulnerabilidades y generacion de reportes.

> **AVISO LEGAL:** Esta herramienta esta autorizada para uso SOLO en sistemas que poseas o tengas permiso escrito explicito para probar. El acceso no autorizado a sistemas informaticos es ilegal. Los usuarios son los unicos responsables del cumplimiento de todas las leyes aplicables. Los autores no asumen responsabilidad por mal uso.

---

## Motivacion

Los profesionales de seguridad necesitan una herramienta unificada y auditable que combine reconocimiento, escaneo y deteccion de vulnerabilidades en un solo pipeline con protecciones legales integradas. La mayoria de las herramientas existentes operan de forma aislada, carecen de validacion de alcance y no proporcionan registro de auditoria.

redteam-analyzer aborda estas carencias:

- **Pipeline unificado** -- recon, scan, vuln y report en un solo comando
- **Protecciones legales en codigo** -- validacion de alcance, rate limiting y control de autenticacion aplicados a nivel del motor
- **Registro de auditoria** -- cada accion registrada con marca de tiempo, objetivo, modulo y resultado
- **Arquitectura basada en plugins** -- modulos extensibles que se ejecutan de forma independiente y fallan gracefulmente
- **Visibilidad de progreso** -- progreso de nmap en tiempo real con verbosidad configurable

---

## Stack Tecnologico

| Componente | Tecnologia |
|------------|------------|
| Lenguaje | Python 3.10+ |
| Framework CLI | Typer |
| Salida Terminal | Rich |
| Modelos de Datos | Pydantic v2 |
| Cliente HTTP | httpx |
| Formato de Config | YAML |
| Plantillas | Jinja2 |
| Testing | pytest, pytest-asyncio |
| Verificacion de Tipos | mypy |
| Linting | ruff |

### Herramientas Externas

| Herramienta | Proposito | Requerida |
|-------------|-----------|:---------:|
| nmap | Escaneo de puertos | Si |
| nuclei | Escaneo de plantillas de vulnerabilidades | Opcional |
| whatweb | Fingerprinting web | Opcional |
| masscan | Escaneo rapido de puertos (alternativa a nmap) | Opcional |

---

## Instalacion

```bash
git clone https://github.com/your-org/redteam-analyzer.git
cd redteam-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Consulta [docs/es/deployment.md](docs/es/deployment.md) para instrucciones detalladas de despliegue incluyendo la instalacion de herramientas externas.

---

## Inicio Rapido

```bash
# Dry run (sin llamadas de red -- seguro para probar configuracion)
redteam-analyzer scan example.com --dry-run

# Escaneo completo contra un objetivo autorizado
redteam-analyzer scan 192.168.1.100 --auth-token YOUR_TOKEN

# Solo reconocimiento pasivo
redteam-analyzer recon example.com --passive-only

# Escaneo con progreso en tiempo real
redteam-analyzer scan 10.129.95.191 -vv

# Generar reporte desde resultados existentes
redteam-analyzer report scan-results.json -f html -f markdown -o report
```

---

## Comandos

| Comando | Descripcion |
|---------|-------------|
| `redteam-analyzer scan <target>` | Pipeline completo de escaneo de seguridad |
| `redteam-analyzer recon <target>` | Solo reconocimiento |
| `redteam-analyzer report <file>` | Generar reporte desde resultados JSON |
| `redteam-analyzer config validate <file>` | Validar archivo de configuracion |
| `redteam-analyzer plugin list` | Listar plugins disponibles |

### Niveles de Verbosidad

| Flag | Salida |
|------|--------|
| (ninguno) | Spinner con estado de la fase |
| `-v` | Hallazgos detallados despues del escaneo |
| `-vv` | Porcentaje de progreso de nmap en tiempo real |
| `-vvv` | Salida cruda de nmap linea por linea |

---

## Modulos

| Modulo | Descripcion | Requiere Auth |
|--------|-------------|:---:|
| `recon` | Reconocimiento pasivo y activo | No |
| `scan` | Escaneo de puertos via nmap o masscan | No |
| `vuln` | Emparejamiento CVE y escaneo de plantillas Nuclei | Si |
| `report` | Generacion de reportes JSON, HTML y Markdown | No |

---

## Configuracion

```bash
cp config.example.yaml config.yaml
redteam-analyzer config validate config.yaml
redteam-analyzer scan example.com -c config.yaml
```

Todas las opciones admiten sobreescritura via variables de entorno con el prefijo `RTA_`. Consulta [docs/es/usage.md](docs/es/usage.md) para la referencia completa.

---

## Documentacion

| Documento | Descripcion |
|-----------|-------------|
| [Arquitectura](docs/es/architecture.md) | Arquitectura tecnica y decisiones de diseno |
| [Guia de Despliegue](docs/es/deployment.md) | Instalacion paso a paso en Kali Linux |
| [Guia de Uso](docs/es/usage.md) | Referencia completa de comandos y flujo de trabajo |
| [Solucion de Problemas](docs/es/troubleshooting.md) | Problemas conocidos y sus soluciones |

### Documentacion en Ingles

| Document | Description |
|----------|-------------|
| [Architecture](docs/en/architecture.md) | Technical architecture and design decisions |
| [Deployment Guide](docs/en/deployment.md) | Step-by-step installation on Kali Linux |
| [Usage Guide](docs/en/usage.md) | Complete command reference and workflow |
| [Troubleshooting](docs/en/troubleshooting.md) | Known issues and their solutions |

---

## Estructura del Proyecto

```
redteam-analyzer/
├── src/redteam_analyzer/
│   ├── cli/              # App Typer + salida Rich
│   ├── core/             # Motor, modelos, validacion de alcance
│   ├── modules/          # Plugins de escaneo (recon, scan, vuln, report)
│   └── utils/            # Rate limiter, registro de auditoria, herramientas externas
├── tests/                # 135 tests (unitarios, integracion, E2E)
├── docs/                 # Documentacion (en/, es/)
├── config.example.yaml   # Configuracion de ejemplo
└── pyproject.toml        # Configuracion del proyecto
```

---

## Desarrollo

```bash
pip install -e ".[dev]"
pytest -v                          # Ejecutar todos los tests
pytest --cov=redteam_analyzer      # Reporte de cobertura
mypy src/                          # Verificacion de tipos
ruff check src/                    # Linting
```

---

## Licencia

MIT
