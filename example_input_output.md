# Ejemplo de entrada y salida del SOC Security Log Analyzer

Este archivo muestra ejemplos de uso de `log_analyzer.py` con los logs de ejemplo incluidos en el repositorio.

---

## Ejemplo 1: auth.log (SSH)

### Comando

```bash
python log_analyzer.py logs/example_auth.log --output examples/output_auth.json --anonymize --anonymize-mode mask
```

### Fragmento de entrada (`logs/example_auth.log`)

```text
2026-11-18T00:24:05.176801+01:00 ubuntu-prod-01 sshd[7947]: Invalid user admin_backup from 10.0.2.6 port 44860
2026-11-18T00:24:17.014275+01:00 ubuntu-prod-01 sshd[7947]: Failed password for invalid user admin_backup from 10.0.2.6 port 44860 ssh2
...
```

### Salida JSON (`examples/output_auth.json`)

```json
{
  "log_type": "auth",
  "analyzed_lines": 150,
  "suspicious_ips": 2,
  "generated_at": "2026-11-23T15:58:35.784791",
  "summary": {
    "10.0.X.X": {
      "total_events": 111,
      "failed_attempts": 109,
      "success_attempts": 2,
      "users_targeted": ["admin_backup", "analista", "invalid", "root"],
      "threat_classification": "possible_successful_brute_force",
      "reasons": [
        "109 intentos fallidos en menos de 120s",
        "4 usuarios diferentes probados",
        "honeytoken admin_backup atacado",
        "múltiples fallos seguidos de un login exitoso"
      ],
      "first_seen": "2026-11-17T23:53:34.365637+01:00",
      "last_seen": "2026-11-18T14:15:15.568777+01:00"
    },
    "127.0.X.X": {
      "total_events": 20,
      "failed_attempts": 20,
      "success_attempts": 0,
      "users_targeted": ["hacker_test", "invalid"],
      "threat_classification": "brute_force",
      "reasons": ["20 intentos fallidos en menos de 120s"],
      "first_seen": "2026-11-17T23:58:47.610480+01:00",
      "last_seen": "2026-11-18T00:00:10.429756+01:00"
    }
  }
}
```

### Interpretación

- La IP anonimizada `10.0.X.X` realizó 109 intentos fallidos de SSH contra varios usuarios.
- Se detectó el ataque al honeytoken `admin_backup`.
- Tras los fallos hubo logins exitosos, por lo que se clasifica como posible fuerza bruta exitosa.
- La IP `127.0.X.X` muestra una secuencia de 20 intentos fallidos en menos de 120 segundos.

---

## Ejemplo 2: access.log (Apache)

### Comando

```bash
python log_analyzer.py logs/example_access.log --output examples/output_access.csv --format csv --anonymize --anonymize-mode mask
```

### Fragmento de entrada (`logs/example_access.log`)

```text
10.0.2.6 - - [20/Nov/2026:01:55:36 +0100] "GET /protected/ HTTP/1.1" 404 490 "-" "Mozilla/4.0 (Hydra)"
10.0.2.6 - - [20/Nov/2026:01:56:47 +0100] "GET /index.php?id=1 HTTP/1.1" 404 471 "-" "sqlmap/1.0"
...
```

### Salida CSV (`examples/output_access.csv`)

```csv
ip,total_events,threat_classification,reasons,first_seen,last_seen,suspicious_events,attack_indicators
10.0.X.X,200,scanning,"User-Agent de herramienta de escaneo (17 peticiones); 195 peticiones con indicadores maliciosos; 21 respuestas 404 (fuzzing de directorios)",2026-11-20T01:53:11+01:00,2026-11-20T17:33:10+01:00,195,"{""scanner_tool"": 17, ""not_found"": 21, ""sensitive_path"": 1, ""timeout"": 174}"
```

### Interpretación

- La IP anonimizada realizó 200 peticiones web de ejemplo.
- 195 de ellas tenían indicadores maliciosos (SQLi, XSS, LFI, etc.).
- 17 peticiones usaban User-Agent de herramientas de escaneo (Hydra, sqlmap, etc.).
- 21 respuestas 404 indican fuzzing de directorios.

---

## Ejemplo 3: anonimización completa

### Comando

```bash
python log_analyzer.py logs/example_auth.log --output reporte_anon.json --anonymize --anonymize-mode full --min-level high
```

### Efecto

- Todas las IPs se reemplazan por `X.X.X.X`.
- Solo se incluyen amenazas de nivel alto (`brute_force`, `honeytoken_triggered`, etc.).
- Útil para compartir resultados sin exponer direcciones reales.

---

## Ejemplo 4: salida filtrada por nivel de amenaza

### Comando

```bash
python log_analyzer.py logs/example_auth.log --output reporte_medium.json --min-level medium
```

### Efecto

- Se excluyen las IPs clasificadas como `normal`.
- Se conservan `brute_force`, `possible_successful_brute_force`, `honeytoken_triggered` y `login_after_failures`.
