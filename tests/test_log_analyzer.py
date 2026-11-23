"""
Pruebas unitarias para log_analyzer.py.

Ejecutar:
    python -m unittest tests.test_log_analyzer
"""

import json
import tempfile
import unittest
from pathlib import Path

import log_analyzer as la


class TestLogDetection(unittest.TestCase):
    """Verifica la detección del tipo de log."""

    def test_detect_auth_log(self):
        lines = [
            "2026-11-20T12:00:00+00:00 ubuntu sshd[123]: Failed password for admin from 10.0.2.6 port 12345 ssh2",
        ]
        self.assertEqual(la.detect_log_type(lines), "auth")

    def test_detect_access_log(self):
        lines = [
            '10.0.2.6 - - [20/Nov/2026:12:00:00 +0100] "GET / HTTP/1.1" 200 123 "-" "curl/8.0"',
        ]
        self.assertEqual(la.detect_log_type(lines), "access")

    def test_detect_unknown_log_raises(self):
        lines = ["esto no es un log reconocible"]
        with self.assertRaises(ValueError):
            la.detect_log_type(lines)


class TestAuthParsing(unittest.TestCase):
    """Verifica el parseo de auth.log."""

    def test_parse_failed_password(self):
        lines = [
            "2026-11-20T12:00:00+00:00 ubuntu sshd[123]: Failed password for admin from 10.0.2.6 port 12345 ssh2",
        ]
        events = la.parse_auth_log(lines)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ip"], "10.0.2.6")
        self.assertEqual(events[0]["user"], "admin")
        self.assertEqual(events[0]["event_type"], "failed")

    def test_parse_invalid_user(self):
        lines = [
            "2026-11-20T12:00:00+00:00 ubuntu sshd[123]: Invalid user admin_backup from 10.0.2.6 port 12345",
        ]
        events = la.parse_auth_log(lines)
        self.assertEqual(events[0]["event_type"], "invalid_user")

    def test_ignore_non_ssh_events(self):
        lines = [
            "2026-11-20T12:00:00+00:00 ubuntu systemd-logind[988]: New seat seat0.",
        ]
        events = la.parse_auth_log(lines)
        self.assertEqual(len(events), 0)


class TestAccessParsing(unittest.TestCase):
    """Verifica el parseo de access.log."""

    def test_parse_normal_request(self):
        lines = [
            '10.0.2.6 - - [20/Nov/2026:12:00:00 +0100] "GET / HTTP/1.1" 200 123 "-" "curl/8.0"',
        ]
        events = la.parse_access_log(lines)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["ip"], "10.0.2.6")
        self.assertEqual(events[0]["status"], 200)
        self.assertEqual(events[0]["event_type"], "normal")

    def test_detect_sqli(self):
        lines = [
            '10.0.2.6 - - [20/Nov/2026:12:00:00 +0100] "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 404 123 "-" "curl/8.0"',
        ]
        events = la.parse_access_log(lines)
        self.assertEqual(events[0]["event_type"], "suspicious")
        self.assertIn("sqli", events[0]["indicators"])

    def test_detect_scanner_user_agent(self):
        lines = [
            '10.0.2.6 - - [20/Nov/2026:12:00:00 +0100] "GET /admin HTTP/1.1" 404 123 "-" "Mozilla/4.0 (Hydra)"',
        ]
        events = la.parse_access_log(lines)
        self.assertIn("scanner_tool", events[0]["indicators"])


class TestThreatAnalysis(unittest.TestCase):
    """Verifica la clasificación de amenazas."""

    def test_brute_force_detection(self):
        events = []
        for i in range(6):
            events.append({
                "timestamp": f"2026-11-20T12:00:{i:02d}+00:00",
                "ip": "10.0.2.6",
                "user": "root",
                "event_type": "failed",
                "raw": "",
            })
        summary = la.analyze_auth_events(events)
        self.assertEqual(summary["10.0.2.6"]["threat_classification"], "brute_force")

    def test_honeytoken_detection(self):
        events = [
            {
                "timestamp": "2026-11-20T12:00:00+00:00",
                "ip": "10.0.2.6",
                "user": "admin_backup",
                "event_type": "failed",
                "raw": "",
            },
        ]
        summary = la.analyze_auth_events(events)
        self.assertEqual(summary["10.0.2.6"]["threat_classification"], "honeytoken_triggered")


class TestExport(unittest.TestCase):
    """Verifica la exportación a JSON y CSV."""

    def test_export_json(self):
        data = {
            "log_type": "auth",
            "analyzed_lines": 1,
            "suspicious_ips": 1,
            "generated_at": "2026-11-20T12:00:00",
            "summary": {},
        }
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = Path(f.name)
        try:
            la.export_json(data, path)
            loaded = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(loaded["log_type"], "auth")
        finally:
            path.unlink(missing_ok=True)

    def test_export_csv(self):
        summary = {
            "10.0.2.6": {
                "total_events": 1,
                "failed_attempts": 1,
                "success_attempts": 0,
                "users_targeted": ["root"],
                "threat_classification": "brute_force",
                "reasons": ["test"],
                "first_seen": None,
                "last_seen": None,
            }
        }
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = Path(f.name)
        try:
            la.export_csv(summary, path, "auth")
            content = path.read_text(encoding="utf-8")
            self.assertIn("10.0.2.6", content)
            self.assertIn("brute_force", content)
        finally:
            path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
