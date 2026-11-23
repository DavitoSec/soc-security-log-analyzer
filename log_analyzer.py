#!/usr/bin/env python3
"""
SOC Security Log Analyzer

Analiza logs SSH (auth.log) y Apache (access.log) para extraer IPs atacantes,
clasificar amenazas y exportar resúmenes en JSON o CSV.

Uso básico:
    python log_analyzer.py logs/example_auth.log --output reporte.json
    python log_analyzer.py logs/example_access.log --output reporte.csv --format csv
    python log_analyzer.py logs/example_auth.log --anonymize --output reporte_anon.json
"""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Umbrales y patrones de detección
# ---------------------------------------------------------------------------
# Fuerza bruta: >= 5 intentos fallidos en <= 120 segundos.
BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_SECONDS = 120

# Intentos de autenticación fallidos en auth.log.
SSH_FAILURE_PATTERNS = [
    re.compile(r"Failed password", re.IGNORECASE),
    re.compile(r"Invalid user", re.IGNORECASE),
    re.compile(r"Connection closed by authenticating user", re.IGNORECASE),
    re.compile(r"Did not receive identification string", re.IGNORECASE),
]

# Autenticación exitosa en auth.log.
SSH_SUCCESS_PATTERNS = [
    re.compile(r"Accepted password", re.IGNORECASE),
    re.compile(r"Accepted publickey", re.IGNORECASE),
]

# Payloads sospechosos en URLs de access.log.
WEB_ATTACK_PATTERNS = {
    "sqli": re.compile(r"(\%27)|(')|(--)|(\%23)|(#)|(\bunion\b)|(\bselect\b)|(\binsert\b)|(\bdelete\b)|(\bdrop\b)|(\bupdate\b)", re.IGNORECASE),
    "xss": re.compile(r"(<script)|(%3Cscript)|(javascript:)|(onerror=)|(onload=)|(<img)", re.IGNORECASE),
    "lfi": re.compile(r"(\.\./)|(\%2e\%2e\%2f)|(\%252e\%252e\%252f)|(/etc/passwd)|(/proc/self)", re.IGNORECASE),
    "cmd_injection": re.compile(r"(\;)|(\&\&)|(\|\|)|(\`|(\$\())", re.IGNORECASE),
}

# User-Agent asociados a herramientas de escaneo/ataque.
SCANNER_USER_AGENTS = [
    re.compile(r"hydra", re.IGNORECASE),
    re.compile(r"nikto", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"wapiti", re.IGNORECASE),
]

# Rutas sensibles que no deberían ser accesibles públicamente.
SENSITIVE_PATHS = [
    re.compile(r"^/admin", re.IGNORECASE),
    re.compile(r"^/wp-admin", re.IGNORECASE),
    re.compile(r"^/phpmyadmin", re.IGNORECASE),
    re.compile(r"^/config", re.IGNORECASE),
    re.compile(r"\.sql$", re.IGNORECASE),
    re.compile(r"\.bak$", re.IGNORECASE),
    re.compile(r"\.zip$", re.IGNORECASE),
]


def detect_log_type(lines: List[str]) -> str:
    """
    Detecta si el log es de tipo SSH (auth.log) o Apache (access.log).

    auth.log contiene sshd, pam_unix o systemd-logind.
    access.log comienza con IP seguida de ident, usuario y petición HTTP.
    """
    for line in lines[:50]:
        if re.search(r"sshd\[|pam_unix|systemd-logind|Failed password|Accepted password", line):
            return "auth"
        if re.match(r"^\d+\.\d+\.\d+\.\d+ .*? \"\w+ /.* HTTP/", line):
            return "access"
    raise ValueError("No se pudo detectar el tipo de log. Asegúrate de que sea auth.log o access.log.")


def anonymize_ip(ip: str, mode: str = "mask") -> str:
    """
    Anonimiza una dirección IP para compartir logs sin exponer IPs reales.

    Modos:
        - "mask": 10.0.2.6 -> 10.0.X.X (conserva red, ofusca host)
        - "full":  10.0.2.6 -> X.X.X.X
        - "hash":  10.0.2.6 -> hash corto (pseudonimización)
    """
    if mode == "full":
        return "X.X.X.X"
    if mode == "hash":
        return f"ip_{hash(ip) & 0xFFFFFFFF:08x}"

    octets = ip.split(".")
    if len(octets) == 4:
        return f"{octets[0]}.{octets[1]}.X.X"
    return "X.X.X.X"


def parse_iso_timestamp(text: str) -> Optional[datetime]:
    """
    Parsea timestamps en formato ISO 8601.
    Ejemplo: 2026-11-17T21:57:56.857070+00:00
    """
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def parse_apache_timestamp(text: str) -> Optional[datetime]:
    """
    Parsea timestamps de Apache access.log.
    Ejemplo: 20/Nov/2026:01:53:11 +0100
    """
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse_auth_log(lines: List[str]) -> List[Dict]:
    """
    Parsea líneas de auth.log y extrae eventos de autenticación SSH.

    Se filtran líneas relacionadas con sshd o autenticación PAM/SSH.
    Eventos de systemd-logind, CRON u otros servicios se ignoran.
    """
    events = []
    iso_re = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?)")
    legacy_re = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
    ssh_line_re = re.compile(r"sshd\[|Failed password|Accepted password|Accepted publickey|Invalid user|Connection closed by authenticating user|Did not receive identification string")

    for line in lines:
        line = line.strip()
        if not line or not ssh_line_re.search(line):
            continue

        timestamp = None
        iso_match = iso_re.match(line)
        if iso_match:
            timestamp = parse_iso_timestamp(iso_match.group(1))
        else:
            legacy_match = legacy_re.match(line)
            if legacy_match:
                ts_text = f"{datetime.now().year} {legacy_match.group(1)}"
                try:
                    timestamp = datetime.strptime(ts_text, "%Y %b %d %H:%M:%S")
                except ValueError:
                    timestamp = None

        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
        if not ip_match:
            continue
        ip = ip_match.group(1)

        user_match = re.search(r"(?:for|user)\s+(\S+)", line)
        user = user_match.group(1) if user_match else "unknown"
        user = user.strip("'\"[]")

        event_type = "other"
        for pattern in SSH_FAILURE_PATTERNS:
            if pattern.search(line):
                event_type = "failed"
                break
        for pattern in SSH_SUCCESS_PATTERNS:
            if pattern.search(line):
                event_type = "success"
                break

        if "Invalid user" in line:
            event_type = "invalid_user"

        events.append({
            "timestamp": timestamp.isoformat() if timestamp else None,
            "ip": ip,
            "user": user,
            "event_type": event_type,
            "raw": line,
        })

    return events


def parse_access_log(lines: List[str]) -> List[Dict]:
    """
    Parsea líneas de access.log de Apache (formato combined).

    Extrae IP, método, ruta, código de estado, user-agent y detecta
    indicadores de ataques web (SQLi, XSS, LFI, escaneos, etc.).
    """
    apache_re = re.compile(
        r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+'
        r'(?P<ident>\S+)\s+'
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\S+)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<user_agent>[^"]*)"'
    )

    events = []
    for line in lines:
        line = line.strip()
        if not line:
            continue

        match = apache_re.match(line)
        if not match:
            continue

        data = match.groupdict()
        timestamp = parse_apache_timestamp(data["time"])

        indicators = []
        path = data["path"]
        user_agent = data["user_agent"]
        status = data["status"]

        for attack_name, pattern in WEB_ATTACK_PATTERNS.items():
            if pattern.search(path):
                indicators.append(attack_name)

        for scanner in SCANNER_USER_AGENTS:
            if scanner.search(user_agent):
                indicators.append("scanner_tool")
                break

        for sensitive in SENSITIVE_PATHS:
            if sensitive.search(path):
                indicators.append("sensitive_path")
                break

        if status == "404":
            indicators.append("not_found")

        if status == "408":
            indicators.append("timeout")

        events.append({
            "timestamp": timestamp.isoformat() if timestamp else None,
            "ip": data["ip"],
            "method": data["method"],
            "path": path,
            "status": int(status),
            "user_agent": user_agent,
            "event_type": "suspicious" if indicators else "normal",
            "indicators": list(set(indicators)),
            "raw": line,
        })

    return events


def analyze_auth_events(events: List[Dict]) -> Dict:
    """
    Agrega eventos auth.log por IP y detecta patrones de ataque.

    Criterios de fuerza bruta:
        - >= BRUTE_FORCE_THRESHOLD intentos fallidos en BRUTE_FORCE_WINDOW_SECONDS.
        - >= 3 usuarios diferentes intentados (indica diccionario).
        - Presencia del honeytoken admin_backup.
    """
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event["ip"]].append(event)

    summary = {}
    for ip, ip_events in by_ip.items():
        failed = [e for e in ip_events if e["event_type"] in ("failed", "invalid_user")]
        success = [e for e in ip_events if e["event_type"] == "success"]
        users = {e["user"] for e in ip_events if e["user"] != "unknown"}

        brute_force = _detect_temporal_burst(failed)

        threat = "normal"
        reasons = []
        if len(failed) >= BRUTE_FORCE_THRESHOLD and brute_force:
            threat = "brute_force"
            reasons.append(f"{len(failed)} intentos fallidos en menos de {BRUTE_FORCE_WINDOW_SECONDS}s")
        if len(users) >= 3:
            threat = "brute_force" if threat == "normal" else threat
            reasons.append(f"{len(users)} usuarios diferentes probados")
        if "admin_backup" in users:
            threat = "honeytoken_triggered"
            reasons.append("honeytoken admin_backup atacado")
        if success and failed:
            if len(failed) >= BRUTE_FORCE_THRESHOLD:
                threat = "possible_successful_brute_force"
                reasons.append("múltiples fallos seguidos de un login exitoso")
            else:
                threat = "login_after_failures"
                reasons.append("fallos menores antes de login exitoso")

        summary[ip] = {
            "total_events": len(ip_events),
            "failed_attempts": len(failed),
            "success_attempts": len(success),
            "users_targeted": sorted(users),
            "threat_classification": threat,
            "reasons": reasons,
            "first_seen": min((e["timestamp"] for e in ip_events if e["timestamp"]), default=None),
            "last_seen": max((e["timestamp"] for e in ip_events if e["timestamp"]), default=None),
        }

    return summary


def _detect_temporal_burst(failed_events: List[Dict]) -> bool:
    """
    Devuelve True si hay BRUTE_FORCE_THRESHOLD o más eventos fallidos
    dentro de una ventana de BRUTE_FORCE_WINDOW_SECONDS.
    """
    timestamps = [
        datetime.fromisoformat(e["timestamp"])
        for e in failed_events
        if e["timestamp"]
    ]
    timestamps.sort()

    if len(timestamps) < BRUTE_FORCE_THRESHOLD:
        return False

    for i in range(len(timestamps) - BRUTE_FORCE_THRESHOLD + 1):
        window_start = timestamps[i]
        window_end = timestamps[i + BRUTE_FORCE_THRESHOLD - 1]
        if (window_end - window_start).total_seconds() <= BRUTE_FORCE_WINDOW_SECONDS:
            return True
    return False


def analyze_access_events(events: List[Dict]) -> Dict:
    """
    Agrega eventos access.log por IP y clasifica la actividad web.
    """
    by_ip = defaultdict(list)
    for event in events:
        by_ip[event["ip"]].append(event)

    summary = {}
    for ip, ip_events in by_ip.items():
        suspicious = [e for e in ip_events if e["event_type"] == "suspicious"]
        not_found = [e for e in ip_events if "not_found" in e["indicators"]]
        scanner = [e for e in ip_events if "scanner_tool" in e["indicators"]]

        attack_counts = defaultdict(int)
        for event in suspicious:
            for indicator in event["indicators"]:
                attack_counts[indicator] += 1

        threat = "normal"
        reasons = []
        if scanner:
            threat = "scanning"
            reasons.append(f"User-Agent de herramienta de escaneo ({len(scanner)} peticiones)")
        if suspicious:
            threat = "web_attack" if threat == "normal" else threat
            reasons.append(f"{len(suspicious)} peticiones con indicadores maliciosos")
        if len(not_found) >= 20:
            threat = "scanning" if threat == "normal" else threat
            reasons.append(f"{len(not_found)} respuestas 404 (fuzzing de directorios)")

        summary[ip] = {
            "total_events": len(ip_events),
            "suspicious_events": len(suspicious),
            "attack_indicators": dict(attack_counts),
            "threat_classification": threat,
            "reasons": reasons,
            "first_seen": min((e["timestamp"] for e in ip_events if e["timestamp"]), default=None),
            "last_seen": max((e["timestamp"] for e in ip_events if e["timestamp"]), default=None),
        }

    return summary


def export_json(data: Dict, output_path: Path) -> None:
    """Exporta el resumen a JSON con indentación legible."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def export_csv(data: Dict, output_path: Path, log_type: str) -> None:
    """Exporta el resumen a CSV."""
    if not data:
        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "message"])
            writer.writerow(["N/A", "No se encontraron eventos sospechosos"])
        return

    rows = []
    for ip, stats in data.items():
        row = {
            "ip": ip,
            "total_events": stats["total_events"],
            "threat_classification": stats["threat_classification"],
            "reasons": "; ".join(stats["reasons"]),
            "first_seen": stats["first_seen"],
            "last_seen": stats["last_seen"],
        }
        if log_type == "auth":
            row["failed_attempts"] = stats.get("failed_attempts", 0)
            row["success_attempts"] = stats.get("success_attempts", 0)
            row["users_targeted"] = ",".join(stats.get("users_targeted", []))
        else:
            row["suspicious_events"] = stats.get("suspicious_events", 0)
            row["attack_indicators"] = json.dumps(stats.get("attack_indicators", {}), ensure_ascii=False)
        rows.append(row)

    if not rows:
        return

    fieldnames = list(rows[0].keys())
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(
        description="Analiza logs SSH (auth.log) o Apache (access.log) en busca de actividad sospechosa."
    )
    parser.add_argument("log_file", help="Ruta al archivo de log a analizar.")
    parser.add_argument("--output", "-o", required=True, help="Ruta del archivo de salida.")
    parser.add_argument(
        "--format",
        "-f",
        choices=["json", "csv"],
        default="json",
        help="Formato de salida (por defecto: json).",
    )
    parser.add_argument(
        "--anonymize",
        "-a",
        action="store_true",
        help="Anonimiza las direcciones IP en la salida.")
    parser.add_argument(
        "--anonymize-mode",
        choices=["mask", "full", "hash"],
        default="mask",
        help="Modo de anonimización de IPs (por defecto: mask).",
    )
    parser.add_argument(
        "--min-level",
        choices=["low", "medium", "high"],
        default="low",
        help="Nivel mínimo de amenaza a incluir en el resumen (low: todo, medium: excluye normal, high: solo brute_force/web_attack/honeytoken).",
    )

    args = parser.parse_args()

    log_path = Path(args.log_file)
    if not log_path.exists():
        print(f"Error: el archivo '{log_path}' no existe.", file=sys.stderr)
        sys.exit(1)

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    if not lines:
        print("Error: el archivo de log está vacío.", file=sys.stderr)
        sys.exit(1)

    log_type = detect_log_type(lines)
    print(f"Tipo de log detectado: {log_type}")

    if log_type == "auth":
        events = parse_auth_log(lines)
        summary = analyze_auth_events(events)
    else:
        events = parse_access_log(lines)
        summary = analyze_access_events(events)

    if args.anonymize:
        summary = {
            anonymize_ip(ip, args.anonymize_mode): stats
            for ip, stats in summary.items()
        }

    if args.min_level == "medium":
        summary = {ip: s for ip, s in summary.items() if s["threat_classification"] != "normal"}
    elif args.min_level == "high":
        high_threats = {"brute_force", "possible_successful_brute_force", "web_attack", "honeytoken_triggered", "scanning"}
        summary = {ip: s for ip, s in summary.items() if s["threat_classification"] in high_threats}

    report = {
        "log_type": log_type,
        "analyzed_lines": len(lines),
        "suspicious_ips": len(summary),
        "generated_at": datetime.now().isoformat(),
        "summary": summary,
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format == "json":
        export_json(report, output_path)
    else:
        export_csv(summary, output_path, log_type)

    print(f"Análisis completado. Resultados guardados en: {output_path}")
    print(f"IPs sospechosas detectadas: {len(summary)}")


if __name__ == "__main__":
    main()
