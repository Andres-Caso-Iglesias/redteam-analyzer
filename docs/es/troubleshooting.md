# Guia de Solucion de Problemas

Este documento cataloga todos los problemas conocidos encontrados durante el desarrollo y despliegue, junto con sus causas raiz y soluciones.

---

## 1. PluginManager No Descubre Plugins

### Sintomas

```
Plugin 'scan' not found, skipping
Plugin 'recon' not found, skipping
```

Todos los plugins reportan como ausentes a pesar de estar presentes en el arbol de codigo fuente.

### Causa Raiz

El `PluginManager` solo buscaba un atributo `plugin` directamente dentro del `__init__.py` de cada modulo. En este proyecto, cada modulo (`scan`, `recon`, `vuln`, `report`) es un paquete Python con un `__init__.py` vacio y la clase del plugin real viviendo en un submodulo (`scan/plugin.py`, `recon/plugin.py`, etc.).

### Solucion

Se agrego un metodo `_find_base_plugin_in_module()` que busca en el modulo cualquier subclase de `BasePlugin`. Si la busqueda directa falla, el manager ahora itera por los submodulos del modulo buscando la clase del plugin.

**Archivo:** `src/redteam_analyzer/core/plugin_manager.py`

### Leccion Aprendida

Al disenar un sistema de plugins, siempre account for la diferencia entre un paquete (directorio con `__init__.py`) y un modulo (archivo `.py` unico). Los archivos `__init__.py` vacios son comunes en paquetes Python — no asumas que la clase del plugin vive a nivel del paquete.

---

## 2. Rate Limiter TokenBucket Bypass

### Sintomas

El rate limiting no funciona como se esperaba. Los tokens se consumen pero el bucket nunca espera correctamente el relleno cuando esta vacio.

### Causa Raiz

El metodo `_wait_for_token` usaba `<= 0` como condicion para esperar el relleno:

```python
while self.tokens <= 0:
    await asyncio.sleep(wait_time)
```

Cuando `tokens` llegaba a exactamente `0`, el bucle ejecutaria una iteracion mas, esperaria, y luego continuaria con `tokens` todavia en `0` (o un valor fraccionario por relleno parcial). Esto permitia que las solicitudes pasaran sin tener un token completo disponible.

### Solucion

Se cambio la condicion a `< 1`, asegurando que el llamador espere hasta que un token completo este disponible:

```python
while self.tokens < 1:
    await asyncio.sleep(wait_time)
```

**Archivo:** `src/redteam_analyzer/utils/rate_limiter.py`

### Leccion Aprendida

Los rate limiters deben asegurar el consumo atomico de tokens. Un token bucket con capacidad `N` y tasa de relleno `R` tokens/seg solo debe otorgar acceso cuando un token entero este disponible. Las comparaciones de punto flotante cerca de cero son traicioneras — siempre usa desigualdad estricta (`< 1`) en lugar de menor-igual (`<= 0`).

---

## 3. Pydantic v2 Descarta Atributos No Declarados

### Sintomas

El callback de progreso de nmap (`on_progress`) nunca se invocaba. El CLI mostraba solo un spinner estatico "Scanning..." sin actualizaciones de progreso, a pesar de que el callback estaba correctamente definido y asignado.

### Causa Raiz

Pydantic v2 `BaseModel` no permite establecer atributos arbitarios en instancias del modelo. El siguiente codigo falla silenciosamente:

```python
scan_config._on_progress = callback  # Descartado silenciosamente
```

Cuando el plugin de scan luego intenta recuperar el callback:

```python
on_progress = getattr(config, "_on_progress", None)  # Siempre None
```

Obtiene `None` porque Pydantic rechazo la asignacion del atributo.

### Solucion

Se agrego `on_progress` como un campo oficial en `ScanConfig` con `exclude=True` (para que no se serialice) y `arbitrary_types_allowed=True` (para que pueda contener un callable):

```python
from pydantic import BaseModel, ConfigDict, Field

class ScanConfig(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    # ... otros campos ...
    on_progress: Optional[Any] = Field(default=None, exclude=True)
```

**Archivos:**
- `src/redteam_analyzer/core/models.py` — definicion del campo
- `src/redteam_analyzer/cli/main.py` — asignacion cambiada de `_on_progress` a `on_progress`
- `src/redteam_analyzer/modules/scan/plugin.py` — recuperacion cambiada a `getattr(config, "on_progress", None)`

### Leccion Aprendida

Pydantic v2 es estricto con los esquemas de modelos. A diferencia de Pydantic v1 (que tenia `allow_population_by_field_name` y era mas indulgente), v2 rechaza cualquier atributo no declarado en el modelo. Cuando necesitas pasar objetos no serializables (callbacks, pools de conexion, etc.) a traves de un modelo Pydantic, debes declararlos como campos con `exclude=True` y configurar `arbitrary_types_allowed=True` en el modelo.

---

## 4. Progreso de Nmap No Se Muestra (Problema de Carriage Return)

### Sintomas

Incluso despues de arreglar el problema del callback Pydantic, el CLI seguia sin mostrar actualizaciones de progreso de nmap. El spinner permanecia estatico durante todo el escaneo.

### Causa Raiz

Nmap escribe actualizaciones de progreso en stderr usando carriage returns (`\r`) en lugar de newlines (`\n`). La funcion original `_read_stderr_progress` usaba `readline()`, que se bloquea hasta encontrar un caracter `\n`:

```python
async def _read_stderr_progress(stderr_stream, on_progress):
    while True:
        line = await stderr_stream.readline()  # Se bloquea esperando \n
        if not line:
            break
        text = line.decode(errors="replace").rstrip()
        if text:
            on_progress(text)
```

Como nmap nunca envia `\n` durante las actualizaciones de progreso (solo `\r`), `readline()` se bloquea indefinidamente y el callback nunca se invoca.

### Solucion

Se reescribio `_read_stderr_progress` para leer bytes brutos en chunks y dividir tanto en `\r` como en `\n`:

```python
async def _read_stderr_progress(stderr_stream, on_progress):
    buffer = ""
    while True:
        chunk = await stderr_stream.read(1024)
        if not chunk:
            break
        text = chunk.decode(errors="replace")
        for char in text:
            if char in ("\n", "\r"):
                if buffer.strip():
                    on_progress(buffer.strip())
                buffer = ""
            else:
                buffer += char
    if buffer.strip():
        on_progress(buffer.strip())
```

**Archivo:** `src/redteam_analyzer/utils/external_tools.py`

### Leccion Aprendida

Diferentes herramientas usan diferentes convenciones de fin de linea para la salida de progreso. Nmap usa `\r` para sobreescribir la misma linea (como una barra de progreso). Al construir un lector de salida de subprocess que debe manejar progreso de herramientas arbitarias, siempre divide en `\r` y `\n`, y usa lectura basada en chunks en lugar de `readline()`.

Formato de salida de progreso de nmap:
```
SYN Stealth Scan Timing: About 15.35% done; ETC: 14:46 (0:02:51 remaining)
```

---

## 5. Error de Indentacion en el Plugin de Scan

### Sintomas

```
IndentationError: unexpected indent
```

Los tests fallan al recolectar por un error de indentacion en `plugin.py`.

### Causa Raiz

Durante una edicion anterior, se introdujo un nivel extra de indentacion en la linea de asignacion de `on_progress`:

```python
        # Get progress callback from config if available
            on_progress = getattr(config, "on_progress", None)  # Indentacion extra
```

### Solucion

Se elimino la indentacion extra para alinear con el bloque de codigo circundante:

```python
        # Get progress callback from config if available
        on_progress = getattr(config, "on_progress", None)
```

**Archivo:** `src/redteam_analyzer/modules/scan/plugin.py`

### Leccion Aprendida

Siempre ejecuta los tests despues de editar. Los errores de indentacion en Python son errores de sintaxis y crashean el modulo completo. Usa un editor con whitespace visible para detectar estos problemas temprano.

---

## 6. pip install Bloqueado por PEP 668 (Kali Linux)

### Sintomas

```
error: externally-managed-environment
```

`pip install` falla en Kali Linux porque el Python del sistema esta gestionado externamente.

### Causa Raiz

Kali Linux (y muchas distribuciones Linux modernas) marcan el Python del sistema como gestionado externamente segun PEP 668. Esto previene que `pip install` modifique paquetes del sistema para evitar romper herramientas del SO.

### Solucion

Usa un entorno virtual:

```bash
cd ~/Desktop/redteam-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

O usa `--break-system-packages` (no recomendado para produccion):

```bash
pip install -e . --break-system-packages
```

### Leccion Aprendida

Siempre usa entornos virtuales para proyectos Python. Aísla dependencias, evita conflictos con paquetes del sistema, y es la practica estandar en el desarrollo Python moderno.

---

## 7. Flag `--new-terminal` Falla Dentro de tmux

### Sintomas

El flag `-T` para abrir una nueva ventana de terminal no funciona. El comando se cuelga o retrocede a ejecutar en el terminal actual.

### Causa Raiz

El flag `--new-terminal` intenta detectar y lanzar un emulador de terminal grafico (gnome-terminal, xfce4-terminal, etc.). Cuando se ejecuta dentro de tmux, estos terminales graficos pueden no ser accesibles, o las variables de entorno (`$DISPLAY`, `$TERM`) pueden no apuntar a una sesion grafica.

### Estado Actual

Diferido. El flag esta implementado pero retrocede gracefulmente a ejecutar en el terminal actual. Una mejora futura seria detectar tmux y usar `tmux new-window` en su lugar.

### Solucion Alternativa

Ejecuta el escaneo directamente sin `-T`. Usa paneles o ventanas de tmux manualmente para paralelizar trabajo.

---

## Resumen de Todas las Correcciones

| Problema | Archivos Afectados | Solucion |
|----------|---------------------|----------|
| Descubrimiento de submodulos en PluginManager | `core/plugin_manager.py` | Busqueda de submodulos para subclases de `BasePlugin` |
| Bypass del rate limiter TokenBucket | `utils/rate_limiter.py` | Cambio de `<= 0` a `< 1` |
| Pydantic v2 descarta on_progress | `core/models.py`, `cli/main.py`, `modules/scan/plugin.py` | Campo oficial `on_progress` en Pydantic |
| Progreso de nmap no se muestra | `utils/external_tools.py` | Reescritura del lector de stderr para manejar `\r` |
| Error de indentacion | `modules/scan/plugin.py` | Correccion de indentacion extra |
| PEP 668 en Kali | N/A (entorno) | Usar `python3 -m venv .venv` |
| `--new-terminal` en tmux | `cli/terminal.py` | Diferido; retrocede gracefulmente |
