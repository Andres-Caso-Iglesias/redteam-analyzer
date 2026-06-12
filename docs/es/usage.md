# Guia de Uso

Referencia completa para usar redteam-analyzer.

---

## Resumen de Comandos

| Comando | Descripcion |
|---------|-------------|
| `redteam-analyzer scan <target>` | Ejecutar escaneo de seguridad completo (recon + scan + vuln + report) |
| `redteam-analyzer recon <target>` | Ejecutar solo reconocimiento |
| `redteam-analyzer report <file>` | Generar reporte desde resultados JSON existentes |
| `redteam-analyzer config validate <file>` | Validar un archivo de configuracion |
| `redteam-analyzer plugin list` | Listar plugins de escaneo disponibles |

---

## Comando scan

Ejecuta el pipeline completo de escaneo: reconocimiento, escaneo de puertos, deteccion de vulnerabilidades y generacion de reportes.

### Uso Basico

```bash
redteam-analyzer scan <TARGET> [OPTIONS]
```

### Opciones

| Flag | Short | Descripcion |
|------|-------|-------------|
| `--module` | `-m` | Modulos a ejecutar (repetible). Por defecto: todos |
| `--output` | `-o` | Ruta del archivo de salida |
| `--format` | `-f` | Formato de salida: json, html, markdown (repetible) |
| `--config` | `-c` | Ruta del archivo de configuracion |
| `--dry-run` | `-d` | Modo de prueba (sin llamadas de red) |
| `--auth-token` | `-t` | Token de autenticacion para modulos intrusivos |
| `--passive-only` | `-p` | Solo reconocimiento pasivo |
| `--verbose` | `-v` | Nivel de verbosidad (repetible) |
| `--new-terminal` | `-T` | Abrir escaneo en una nueva ventana de terminal |
| `--profile` | | Perfil de escaneo: stealth (predeterminado), normal, aggressive |

### Niveles de Verbosidad

El flag `-v` puede apilarse para aumentar el detalle de la salida:

| Nivel | Flag | Salida |
|-------|------|--------|
| 0 | (ninguno) | Spinner con estado de la fase |
| 1 | `-v` | Hallazgos detallados despues del escaneo |
| 2 | `-vv` | Porcentaje de progreso de nmap en tiempo real |
| 3 | `-vvv` | Salida cruda de nmap linea por linea |

### Perfiles de Escaneo

El flag `--profile` controla la intensidad y el nivel de ruido del escaneo:

| Perfil | Flags | Puertos | Timing | Ruido |
|--------|-------|---------|--------|-------|
| `stealth` (predeterminado) | `-sS --top-ports 1000 -T2 --max-retries 2` | 1000 | Lento | Bajo |
| `normal` | `-sV --top-ports 1000 -T3` | 1000 | Moderado | Medio |
| `aggressive` | `-sV -O` | 65535 | Normal | Alto |

- **stealth**: SYN scan, top 1000 puertos, timing lento para evitar deteccion IDS
- **normal**: Deteccion de version en top 1000 puertos, timing moderado
- **aggressive**: Escaneo completo de puertos con version + deteccion de SO (default original, muy ruidoso)

### Ejemplos

```bash
# Dry run (seguro, sin llamadas de red)
redteam-analyzer scan example.com --dry-run

# Escaneo completo con token de autenticacion
redteam-analyzer scan 192.168.1.100 --auth-token YOUR_TOKEN

# Escaneo con modulos especificos
redteam-analyzer scan example.com -m recon -m scan

# Escaneo con progreso en tiempo real
redteam-analyzer scan 10.129.95.191 -vv

# Escaneo con hallazgos detallados
redteam-analyzer scan 10.129.95.191 -v

# Verbosidad completa (progreso + salida cruda)
redteam-analyzer scan 10.129.95.191 -vvv

# Salida a multiples formatos
redteam-analyzer scan example.com -f json -f html -o results
```

---

## Comando recon

Ejecuta reconocimiento contra un objetivo. Utilico para recopilar informacion antes de un escaneo completo.

### Uso Basico

```bash
redteam-analyzer recon <TARGET> [OPTIONS]
```

### Opciones

| Flag | Short | Descripcion |
|------|-------|-------------|
| `--passive-only` | `-p` | Solo reconocimiento pasivo (sin solicitudes directas al objetivo) |
| `--output` | `-o` | Ruta del archivo de salida |
| `--verbose` | `-v` | Nivel de verbosidad (repetible) |
| `--new-terminal` | `-T` | Abrir reconocimiento en una nueva ventana de terminal |

### Ejemplos

```bash
# Solo reconocimiento pasivo (crt.sh, DNS, VirusTotal, Shodan)
redteam-analyzer recon example.com --passive-only

# Reconocimiento completo (pasivo + activo: fingerprinting, directorios)
redteam-analyzer recon example.com -v
```

### Modulos de Reconocimiento

| Modulo | Tipo | Descripcion |
|--------|------|-------------|
| crt.sh | Pasivo | Registros de transparencia de certificados |
| DNS | Pasivo | Enumeracion de registros DNS |
| VirusTotal | Pasivo | Reputacion del dominio (requiere API key) |
| Shodan | Pasivo | Datos de escaneo global de internet (requiere API key) |
| WhatWeb | Activo | Fingerprinting de tecnologias web |
| Directory bust | Activo | Descubrimiento de rutas ocultas |

---

## Comando report

Genera reportes desde resultados de escaneo guardados previamente.

### Uso Basico

```bash
redteam-analyzer report <FILE> [OPTIONS]
```

### Opciones

| Flag | Short | Descripcion |
|------|-------|-------------|
| `--format` | `-f` | Formato de salida: json, html, markdown (repetible) |
| `--template` | `-t` | Plantilla HTML: default o executive |
| `--output` | `-o` | Ruta del archivo de salida |

### Ejemplos

```bash
# Generar reporte HTML
redteam-analyzer report scan-results.json -f html -o report.html

# Generar resumen ejecutivo
redteam-analyzer report scan-results.json -f html -t executive -o exec-report.html

# Generar todos los formatos
redteam-analyzer report scan-results.json -f json -f html -f markdown -o report
```

---

## Configuracion

### Archivo de Configuracion

Copia la configuracion de ejemplo y personaliza:

```bash
cp config.example.yaml config.yaml
```

```yaml
# config.yaml
scope:
  allowed_targets:
    - "192.168.1.0/24"
    - "example.com"
  rate_limit: 20

modules:
  - recon
  - scan
  - vuln
  - report

scan_backend: nmap
passive_only: false
```

Valida antes de usar:

```bash
redteam-analyzer config validate config.yaml
```

### Variables de Entorno

Todas las opciones de configuracion pueden ser sobreescritas via variables de entorno con el prefijo `RTA_`:

| Variable | Clave de Config | Ejemplo |
|----------|-----------------|---------|
| `RTA_DRY_RUN` | `dry_run` | `true` |
| `RTA_AUTH_TOKEN` | `auth_token` | `your-token` |
| `RTA_MODULES` | `modules` | `recon,scan` |
| `RTA_OUTPUT_FORMAT` | `output_format` | `json,html` |
| `RTA_OUTPUT_PATH` | `output_path` | `results.json` |
| `RTA_PASSIVE_ONLY` | `passive_only` | `true` |
| `RTA_SCAN_BACKEND` | `scan_backend` | `nmap` |
| `RTA_REPORT_TEMPLATE` | `report_template` | `executive` |
| `RTA_SCOPE_RATE_LIMIT` | `scope.rate_limit` | `20` |

---

## Modulos

| Modulo | Descripcion | Requiere Auth |
|--------|-------------|:---:|
| `recon` | Reconocimiento pasivo y activo | No |
| `scan` | Escaneo de puertos via nmap o masscan | No |
| `vuln` | Emparejamiento CVE y escaneo de plantillas Nuclei | Si (para nuclei) |
| `report` | Generacion de reportes JSON, HTML y Markdown | No |

### Orden de Ejecucion de Modulos

Los modulos se ejecutan en el orden definido en la configuracion (por defecto: recon, scan, vuln, report). Cada modulo recibe los resultados acumulados de modulos anteriores.

### Modulos con Restriccion de Autenticacion

El modulo `vuln` usa Nuclei, que puede realizar checks intrusivos. Requiere un `--auth-token` para ejecutarse. Sin el, solo se realizan checks pasivos de vulnerabilidades (emparejamiento CVE).

```bash
# Sin auth: solo emparejamiento CVE
redteam-analyzer scan example.com -m vuln

# Con auth: emparejamiento CVE + plantillas Nuclei
redteam-analyzer scan example.com -m vuln --auth-token YOUR_TOKEN
```

---

## Protecciones Legales

redteam-analyzer aplica varias protecciones legales en codigo:

1. **Validacion de alcance** — Todos los objetivos se validan contra el alcance configurado antes de cualquier llamada de red. Los objetivos fuera de alcance son rechazados con un `ScopeError`.

2. **Rate limiting** — Limites de tasa por dominio y globales previenen una denegacion de servicio accidental.

3. **Control de autenticacion** — Los modulos intrusivos (plantillas Nuclei) requieren autenticacion explicita.

4. **Registro de auditoria** — Cada accion se registra en `audit_log.json` con marca de tiempo, objetivo, modulo, accion y estado de exito/fallo.

5. **Modo dry run** — `--dry-run` ejecuta el pipeline completo sin hacer llamadas de red. Usa esto para verificar la configuracion antes del escaneo en vivo.

---

## Flujo de Trabajo Tipico

```bash
# 1. Preparar entorno
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate

# 2. Validar configuracion
redteam-analyzer config validate config.yaml

# 3. Dry run para verificar
redteam-analyzer scan 10.129.95.191 --dry-run

# 4. Ejecutar reconocimiento primero
redteam-analyzer recon 10.129.95.191 -v

# 5. Escaneo completo con progreso
redteam-analyzer scan 10.129.95.191 -vv

# 6. Generar reporte
redteam-analyzer report scan-results.json -f html -f markdown -o report
```
