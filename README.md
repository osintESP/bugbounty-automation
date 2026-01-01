# Bug Bounty Automation Tool

Herramienta modular para automatizar tareas de bug bounty y verificación de posturas de seguridad.

## 🎯 Características

- **Reconocimiento Automatizado**: Enumeración de subdominios, escaneo de puertos, detección de tecnologías
- **Análisis de Vulnerabilidades**: Integración con herramientas como Nuclei, análisis de headers, detección de secrets
- **Reportes Automáticos**: Generación de reportes en múltiples formatos (JSON, HTML, PDF)
- **Monitoreo Continuo**: Ejecución programada y comparación histórica
- **Arquitectura Modular**: Fácil de extender con nuevas herramientas

## 📋 Requisitos

- Docker y Docker Compose
- Python 3.9+

## 🚀 Instalación

### Opción 1: Docker (Recomendado)

```bash
# Clonar el repositorio
git clone <repo-url>
cd bugbounty

# Levantar servicios
docker-compose up -d
```

### Opción 2: Instalación Local

```bash
# Instalar dependencias de Python
pip install -r requirements.txt

# Instalar herramientas de seguridad
./scripts/install_tools.sh
```

## 🔧 Configuración

Editar `config.yaml` para configurar:

- Targets (dominios a escanear)
- Herramientas a utilizar
- Parámetros de escaneo
- Configuración de base de datos

```yaml
targets:
  - domain: example.com
    scope:
      - "*.example.com"
    exclude:
      - "internal.example.com"

tools:
  recon:
    - subfinder
    - amass
    - nmap
  scan:
    - nuclei
    - httpx
```

## 📖 Uso

### Escaneo Básico

```bash
# Ejecutar reconocimiento completo
python src/main.py recon --target example.com

# Ejecutar escaneo de vulnerabilidades
python src/main.py scan --target example.com

# Pipeline completo
python src/main.py full --target example.com
```

### Generar Reportes

```bash
# Generar reporte HTML
python src/main.py report --target example.com --format html

# Generar reporte JSON
python src/main.py report --target example.com --format json
```

### Modo Continuo

```bash
# Ejecutar monitoreo continuo (cada 24h)
python src/main.py monitor --target example.com --interval 24h
```

## 🏗️ Arquitectura

```
bugbounty/
├── src/
│   ├── main.py              # CLI principal
│   ├── config.py            # Gestor de configuración
│   ├── database.py          # Modelos de base de datos
│   ├── modules/
│   │   ├── recon/           # Módulo de reconocimiento
│   │   ├── scan/            # Módulo de escaneo
│   │   └── report/          # Módulo de reportes
│   └── utils/               # Utilidades
├── config.yaml              # Configuración
├── docker-compose.yml       # Orquestación
└── requirements.txt         # Dependencias
```

## 🛠️ Módulos

### Reconocimiento
- **Subdomain Enumeration**: subfinder, amass, assetfinder
- **Port Scanning**: nmap, masscan
- **Technology Detection**: whatweb, wappalyzer
- **URL Crawling**: gospider, hakrawler, katana

### Escaneo
- **Vulnerability Scanning**: nuclei
- **Security Headers**: custom analysis
- **Secrets Detection**: trufflehog, gitleaks
- **Fuzzing**: ffuf, wfuzz

### Reportes
- **Formatos**: JSON, HTML, PDF, Markdown
- **Dashboard**: API REST para visualización
- **Exportación**: Compatible con Faraday, DefectDojo

## 📊 Base de Datos

La herramienta almacena resultados en PostgreSQL con el siguiente esquema:

- `targets`: Dominios objetivo
- `subdomains`: Subdominios descubiertos
- `ports`: Puertos abiertos
- `vulnerabilities`: Vulnerabilidades encontradas
- `scans`: Historial de escaneos

## 🔐 Seguridad

- Todas las credenciales se almacenan en variables de entorno
- Rate limiting para evitar bloqueos
- Respeto de `robots.txt` y políticas de bug bounty
- Logs detallados de todas las acciones

## 📝 Licencia

MIT License

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor, abre un issue primero para discutir cambios mayores.

## ⚠️ Disclaimer

Esta herramienta está diseñada para uso ético en programas de bug bounty autorizados. El usuario es responsable de obtener permisos apropiados antes de escanear cualquier sistema.
