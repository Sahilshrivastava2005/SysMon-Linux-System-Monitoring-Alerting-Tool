import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import sysmon


class ConfigTests(unittest.TestCase):
    def test_relative_log_directory_is_resolved_from_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            config_dir = Path(temporary)
            config = sysmon.validate_config(
                {"log_dir": "logs", "smtp": {"enabled": False}}, config_dir
            )

            self.assertEqual(config["log_dir"], str((config_dir / "logs").resolve()))
            self.assertEqual(config["cpu_threshold"], 80.0)
            self.assertEqual(config["max_log_bytes"], 5_000_000)

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaisesRegex(sysmon.ConfigError, "cpu_threshold"):
            sysmon.validate_config(
                {"log_dir": "logs", "cpu_threshold": 101}, Path.cwd()
            )

    def test_enabled_smtp_requires_connection_details(self):
        with self.assertRaisesRegex(sysmon.ConfigError, "smtp.host"):
            sysmon.validate_config(
                {"log_dir": "logs", "smtp": {"enabled": True}}, Path.cwd()
            )

    def test_smtp_header_injection_is_rejected(self):
        with self.assertRaisesRegex(sysmon.ConfigError, "smtp.sender_email"):
            sysmon.validate_config(
                {
                    "log_dir": "logs",
                    "smtp": {
                        "enabled": True,
                        "host": "smtp.example.com",
                        "sender_email": "safe@example.com\nBcc: attacker@example.com",
                        "receiver_email": "admin@example.com",
                    },
                },
                Path.cwd(),
            )

    def test_invalid_json_reports_location(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            path.write_text('{"log_dir":', encoding="utf-8")

            with self.assertRaisesRegex(sysmon.ConfigError, "line 1"):
                sysmon.load_config(path)


class MetricTests(unittest.TestCase):
    def test_thresholds_return_all_breaches(self):
        config = {
            "cpu_threshold": 80.0,
            "mem_threshold": 85.0,
            "disk_threshold": 90.0,
            "net_threshold_kbps": 1000.0,
        }
        metrics = {
            "cpu_percent": 81.0,
            "mem_percent": 86.0,
            "disk_percent": 91.0,
            "net_kbps": 1001.0,
        }

        alerts = sysmon.check_thresholds(config, metrics)

        self.assertEqual(len(alerts), 4)
        self.assertIn("High CPU usage", alerts[0])
        self.assertIn("High network throughput", alerts[3])

    def test_equal_threshold_does_not_alert(self):
        config = {
            "cpu_threshold": 80.0,
            "mem_threshold": 80.0,
            "disk_threshold": 90.0,
            "net_threshold_kbps": 1000.0,
        }
        metrics = {
            "cpu_percent": 80.0,
            "mem_percent": 80.0,
            "disk_percent": 90.0,
            "net_kbps": 1000.0,
        }

        self.assertEqual(sysmon.check_thresholds(config, metrics), [])

    def test_network_rate_uses_counter_delta_and_elapsed_time(self):
        first = SimpleNamespace(bytes_sent=1_000, bytes_recv=2_000)
        second = SimpleNamespace(bytes_sent=2_000, bytes_recv=4_000)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.object(sysmon.psutil, "net_io_counters", side_effect=[first, second]),
            patch.object(sysmon.time, "time", side_effect=[100.0, 110.0]),
        ):
            self.assertIsNone(sysmon.get_network_rate(Path(temporary)))
            rate = sysmon.get_network_rate(Path(temporary))

        self.assertAlmostEqual(rate, 2.4)

    def test_corrupt_network_state_is_replaced(self):
        counters = SimpleNamespace(bytes_sent=10, bytes_recv=20)
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "net_state.json"
            state_path.write_text("not json", encoding="utf-8")
            with (
                patch.object(sysmon.psutil, "net_io_counters", return_value=counters),
                patch.object(sysmon.time, "time", return_value=10.0),
            ):
                self.assertIsNone(sysmon.get_network_rate(Path(temporary)))

            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["bytes_sent"], 10)


class LoggingTests(unittest.TestCase):
    def test_log_rotation_keeps_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            log_dir = Path(temporary)
            sysmon.log_message(log_dir, "first", max_bytes=1, backup_count=2)
            sysmon.log_message(log_dir, "second", max_bytes=1, backup_count=2)

            current = (log_dir / "sysmon.log").read_text(encoding="utf-8")
            backup = (log_dir / "sysmon.log.1").read_text(encoding="utf-8")

        self.assertIn("second", current)
        self.assertIn("first", backup)


class EmailTests(unittest.TestCase):
    @staticmethod
    def smtp_config(log_dir: Path):
        return sysmon.validate_config(
            {
                "log_dir": str(log_dir),
                "smtp": {
                    "enabled": True,
                    "host": "smtp.example.com",
                    "port": 587,
                    "security": "starttls",
                    "sender_email": "monitor@example.com",
                    "receiver_email": "admin@example.com",
                },
            },
            log_dir,
        )

    @staticmethod
    def metrics():
        return {
            "cpu_percent": 90.0,
            "mem_percent": 40.0,
            "disk_percent": 50.0,
            "net_kbps": None,
        }

    def test_missing_password_does_not_connect(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.smtp_config(Path(temporary))
            with patch.dict(os.environ, {}, clear=True):
                result = sysmon.send_email_alert(config, self.metrics(), ["High CPU"])

        self.assertIn("is not set", result)

    def test_starttls_email_uses_structured_message(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = self.smtp_config(Path(temporary))
            client = MagicMock()
            server = client.__enter__.return_value
            with (
                patch.dict(os.environ, {"SYSMON_EMAIL_PASSWORD": "secret"}),
                patch.object(sysmon.smtplib, "SMTP", return_value=client) as smtp,
            ):
                result = sysmon.send_email_alert(
                    config, self.metrics(), ["High CPU usage: 90.0%"]
                )

        self.assertEqual(result, "Email alert sent successfully.")
        smtp.assert_called_once_with("smtp.example.com", 587, timeout=15.0)
        server.starttls.assert_called_once()
        server.login.assert_called_once_with("monitor@example.com", "secret")
        message = server.send_message.call_args.args[0]
        self.assertEqual(message["To"], "admin@example.com")
        self.assertIn("High CPU usage", message.get_content())


class CommandTests(unittest.TestCase):
    def test_missing_config_returns_failure_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.json"
            error_output = StringIO()
            with redirect_stderr(error_output):
                status = sysmon.main(["--config", str(missing)])

        self.assertEqual(status, 1)
        self.assertIn("config file not found", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
