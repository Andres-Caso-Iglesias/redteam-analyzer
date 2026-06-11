# Guia de Despliegue

Instrucciones paso a paso para desplegar redteam-analyzer en Kali Linux.

---

## Requisitos Previos

- Kali Linux (probado en la ultima version rolling release)
- Python 3.10 o superior
- Conexion a internet (para instalar dependencias y actualizaciones de herramientas)
- Acceso root o sudo (para instalar herramientas a nivel de sistema)

---

## 1. Instalar Dependencias del Sistema

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-venv python3-pip git
```

---

## 2. Clonar el Repositorio

```bash
cd ~/Desktop
git clone https://github.com/your-org/redteam-analyzer.git
cd redteam-analyzer
```

---

## 3. Crear un Entorno Virtual

Kali Linux bloquea `pip install` directo debido a PEP 668. Siempre usa un entorno virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Para activar el entorno en futuras sesiones:

```bash
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate
```

---

## 4. Instalar el Proyecto

```bash
pip install -e .
```

Esto instala el proyecto en modo editable. Cualquier cambio en el codigo fuente surte efecto inmediatamente sin necesidad de reinstalacion.

### Instalar con Dependencias de Desarrollo

```bash
pip install -e ".[dev]"
```

Esto instala adicionalmente pytest, pytest-asyncio, pytest-cov, mypy y ruff.

---

## 5. Instalar Herramientas Externas

redteam-analyzer delega a herramientas externas para el escaneo. Instala las que necesites:

### nmap (requerido para escaneo de puertos)

```bash
sudo apt install -y nmap
nmap --version
```

### nuclei (requerido para escaneo de plantillas de vulnerabilidades)

Descarga el binario pre-compilado (no se necesita instalar Go):

```bash
cd /tmp
NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
curl -LO "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
unzip "nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
sudo mv nuclei /usr/local/bin/
sudo chmod +x /usr/local/bin/nuclei
nuclei -version
```

### whatweb (requerido para fingerprinting web)

```bash
sudo apt install -y whatweb
whatweb --version
```

### masscan (opcional, alternativa a nmap)

```bash
sudo apt install -y masscan
masscan --version
```

---

## 6. Verificar la Instalacion

```bash
# Activar entorno
source .venv/bin/activate

# Verificar que el CLI esta disponible
redteam-analyzer --help

# Listar plugins disponibles
redteam-analyzer plugin list

# Ejecutar tests
pytest -v

# Dry run (sin llamadas de red)
redteam-analyzer scan example.com --dry-run
```

---

## 7. Configuracion

### Usando un Archivo de Configuracion

```bash
cp config.example.yaml config.yaml
# Editar config.yaml con tus ajustes
redteam-analyzer config validate config.yaml
redteam-analyzer scan example.com -c config.yaml
```

### Usando Variables de Entorno

Todas las opciones de configuracion pueden ser sobreescritas via variables de entorno:

```bash
export RTA_DRY_RUN=true
export RTA_AUTH_TOKEN=your-token-here
export RTA_MODULES=recon,scan
redteam-analyzer scan example.com
```

---

## 8. Ejecutar en tmux

Para escaneos de larga duracion, usa tmux para prevenir la desconexion de la sesion:

```bash
# Crear una nueva sesion de tmux
tmux new-session -s rta

# Activar entorno y ejecutar escaneo
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate
redteam-analyzer scan 10.129.95.191 -vvv

# Desanexar: Ctrl+B, luego D
# Reanexar: tmux attach -t rta
```

---

## Actualizar

```bash
cd ~/Desktop/redteam-analyzer
source .venv/bin/activate
git pull
pip install -e .
```

---

## Desinstalar

```bash
cd ~/Desktop/redteam-analyzer
deactivate  # Salir del entorno virtual
rm -rf .venv
rm -rf src/redteam_analyzer.egg-info
```

---

## Solucion de Problemas

Consulta [troubleshooting.md](troubleshooting.md) para problemas conocidos y sus soluciones.
