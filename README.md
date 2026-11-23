# SOC Security Log Analyzer

![Python](https://img.shields.io/badge/Python-3.7+-3776AB?logo=python&logoColor=white)
![Blue Team](https://img.shields.io/badge/Blue%20Team-SIEM%20Triage-0055FF)
![SOC Tier 1](https://img.shields.io/badge/SOC-Tier%201-FF6600)
![License](https://img.shields.io/badge/License-MIT-green.svg)

Herramienta CLI en Python para el triaje rápido de logs de seguridad orientada a analistas **SOC Tier 1** y equipos **Blue Team**. Analiza archivos de autenticación SSH (`auth.log`) y acceso web Apache (`access.log`), extrae IPs atacantes, clasifica comportamientos de amenaza y exporta resultados en JSON o CSV.

> Ideal para investigaciones *offline*, análisis portátil sin infraestructura y generación de evidencia técnica compartible.

---

## Índice

- [Resumen ejecutivo](#resumen-ejecutivo)
- [Relación con el laboratorio SIEM](#relación-con-el-laboratorio-siem)
- [Funcionalidades clave](#funcionalidades-clave)
- [Requisitos e instalación](#requisitos-e-instalación)
- [Uso](#uso)
- [Resultados de validación](#resultados-de-validación)
- [Estructura del proyecto](#estructura-del-proyecto)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Licencia](#licencia)

---

## Resumen ejecutivo

Este analizador automatiza la fase inicial de triaje de logs:

1. **Detecta** automáticamente si el archivo es `auth.log` o `access.log`.
2. **Parsea** eventos SSH y peticiones web en formato Apache *combined*.
3. **Clasifica** actividad por IP usando patrones RegEx y umbrales de comportamiento.
4. **Anonimiza** direcciones IP para compartir resultados sin exponer infraestructura real.
5. **Exporta** resúmenes en JSON o CSV, con filtrado por nivel de amenaza.

No requiere base de datos ni dependencias externas: solo Python 3.7+.

---

## Relación con el laboratorio SIEM

Este proyecto complementa un laboratorio Wazuh de detección en tiempo real:

| Wazuh (SIEM) | SOC Security Log Analyzer |
|--------------|---------------------------|
| Detección en tiempo real | Triaje *offline* de logs planos |
| Reglas complejas y correlación | Análisis rápido y portable |
| Dashboard visual | Resumen exportable JSON/CSV |
| Requiere infraestructura | Solo requiere Python |

Ambos enfoques cubren las necesidades de un analista SOC Tier 1: detección con SIEM y análisis manual forense de logs. Puedes consultar el laboratorio relacionado en [github.com/DavitoSec/wazuh-soc-detection-lab](https://github.com/DavitoSec/wazuh-soc-detection-lab).

---

## Funcionalidades clave

### Detección automática de formato

El script identifica `auth.log` o `access.log` inspeccionando las primeras líneas, sin necesidad de que el usuario especifique el tipo.

### Análisis de `auth.log` (SSH)

Clasificación comportamental por IP:

- `brute_force`: intentos fallidos masivos dentro de una ventana temporal.
- `possible_successful_brute_force`: múltiples fallos seguidos de un login exitoso.
- `honeytoken_triggered`: ataque contra el usuario trampa `admin_backup`.
- `login_after_failures`: pocos fallos antes de un éxito (posible olvido de contraseña).
- `normal`: actividad no sospechosa.

### Análisis de `access.log` (Apache)

Detección de:

- Payloads de SQL Injection (`union`, `select`, `drop`, etc.).
- Payloads de XSS (`<script>`, `onerror`, `javascript:`, etc.).
- Directory traversal / LFI (`../`, `/etc/passwd`).
- User-Agent de escáneres: **Hydra**, **Nikto**, **Gobuster**, **SQLMap**, **Wapiti**.
- Accesos a rutas sensibles (`/admin`, `/wp-admin`, `/phpmyadmin`, etc.).
- Picos de respuestas `404` como indicio de fuzzing.

### Anonimización de IPs

Tres modos para proteger datos de infraestructura:

- `mask`: `10.0.2.6` → `10.0.X.X` (por defecto).
- `full`: `10.0.2.6` → `X.X.X.X`.
- `hash`: identificador pseudonimizado por IP.

### Exportación flexible

- **JSON**: estructurado, con metadatos del análisis.
- **CSV**: tabla resumen por IP.
- Filtrado por nivel de amenaza: `low`, `medium`, `high`.

---

## Requisitos e instalación

- Python 3.7 o superior.
- Solo librerías estándar: `argparse`, `csv`, `json`, `re`, `sys`, `collections`, `datetime`, `pathlib`, `typing`.

```bash
git clone https://github.com/DavitoSec/soc-security-log-analyzer.git
cd soc-security-log-analyzer
python -m unittest tests.test_log_analyzer
```

---

## Uso

### Análisis básico

```bash
# auth.log a JSON
python log_analyzer.py logs/example_auth.log --output reporte.json

# access.log a CSV
python log_analyzer.py logs/example_access.log --output reporte.csv --format csv
```

### Anonimizar IPs

```bash
python log_analyzer.py logs/example_auth.log --output reporte_anon.json --anonymize
python log_analyzer.py logs/example_auth.log --output reporte_anon.json --anonymize --anonymize-mode full
```

### Filtrar por nivel de amenaza

```bash
python log_analyzer.py logs/example_auth.log --output reporte_high.json --min-level high
python log_analyzer.py logs/example_access.log --output reporte.csv --format csv --min-level high
```

### Ejecutar pruebas

```bash
python -m unittest tests.test_log_analyzer
```

---

## Resultados de validación

Estos resultados se obtuvieron ejecutando la herramienta sobre la telemetría real generada en el laboratorio:

### `auth.log`

- **3 IPs sospechosas** detectadas.
- Una de ellas acumuló **408 intentos fallidos** de SSH.
- Se disparó el honeytoken `admin_backup`.
- Se clasificó como `possible_successful_brute_force` tras detectar un login exitoso después de la ráfaga de fallos.

### `access.log`

- **1 IP atacante** identificada.
- **321 peticiones** con indicadores maliciosos (SQLi, XSS, LFI, etc.).
- User-Agent de herramientas de escaneo (Hydra, Nikto, Gobuster, SQLMap, Wapiti).
- Múltiples respuestas `404` consistentes con fuzzing de directorios.

> Los ejemplos incluidos en `logs/` y `examples/` son fragmentos anonimizados del laboratorio. Puedes reproducir el análisis con los comandos de la sección [Uso](#uso).

---

## Estructura del proyecto

```text
soc-security-log-analyzer/
├── log_analyzer.py              # Script principal
├── README.md                    # Documentación principal
├── LICENSE                      # Licencia MIT
├── .gitignore                   # Archivos ignorados por Git
├── example_input_output.md      # Ejemplos de entrada/salida
├── examples/
│   ├── output_auth.json         # Salida JSON de ejemplo (SSH)
│   └── output_access.csv        # Salida CSV de ejemplo (web)
├── logs/
│   ├── example_auth.log         # Fragmento anonimizado de auth.log
│   └── example_access.log       # Fragmento anonimizado de access.log
└── tests/
    └── test_log_analyzer.py     # Pruebas unitarias
```

| Ruta | Descripción |
|------|-------------|
| `log_analyzer.py` | Código principal: parsers, análisis de amenazas y exportación. |
| `logs/` | Logs de ejemplo anonimizados para pruebas y demostraciones. |
| `examples/` | Salidas de ejemplo en JSON y CSV. |
| `tests/` | Batería de pruebas unitarias con `unittest`. |
| `example_input_output.md` | Guía de ejemplos con comandos y resultados. |

---

## Limitaciones conocidas

- La detección de SQLi/XSS/LFI se basa en **expresiones regulares simples**; puede generar falsos positivos en URLs legítimas.
- Solo se soporta el formato **Apache *combined*** para `access.log`. Logs con formatos personalizados pueden no parsearse.
- Los umbrales de fuerza bruta son **fijos** (`5` intentos en `120` segundos); pueden necesitar ajuste según el entorno.
- El script **carga el archivo completo en memoria**, por lo que logs de varios gigabytes podrían requerir procesamiento por streaming.
- `curl` y otros User-Agent genéricos no se marcan como escáneres; solo se detectan Hydra, Nikto, Gobuster, SQLMap y Wapiti.

---

## Licencia

Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

**Autor:** DavitoSec  
**Rol:** Blue Team / SOC Tier 1
