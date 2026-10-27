import unittest
import os
import tempfile
from analyzer import AuthLogAnalyzer, AuthEvent

SAMPLE_LOG = """Oct 27 10:00:15 server1 sshd[1234]: Accepted publickey for deepika from 192.168.1.50 port 52341 ssh2
Oct 27 10:02:01 server1 sshd[1240]: Failed password for invalid user admin from 203.0.113.45 port 41201 ssh2
Oct 27 10:02:04 server1 sshd[1241]: Failed password for invalid user admin from 203.0.113.45 port 41205 ssh2
Oct 27 10:02:08 server1 sshd[1242]: Failed password for root from 203.0.113.45 port 41210 ssh2
Oct 27 10:02:12 server1 sshd[1243]: Failed password for root from 203.0.113.45 port 41215 ssh2
Oct 27 10:02:18 server1 sshd[1244]: Failed password for invalid user test from 203.0.113.45 port 41220 ssh2
Oct 27 10:05:00 server1 sshd[1250]: Accepted password for deepika from 192.168.1.50 port 52400 ssh2
"""

class TestAuthLogAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = AuthLogAnalyzer(failure_threshold=5)

    def test_parse_accepted_line(self):
        line = "Oct 27 10:00:15 server1 sshd[1234]: Accepted publickey for deepika from 192.168.1.50 port 52341 ssh2"
        event = self.analyzer.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "SUCCESS")
        self.assertEqual(event.user, "deepika")
        self.assertEqual(event.ip, "192.168.1.50")
        self.assertEqual(event.port, 52341)
        self.assertFalse(event.is_invalid_user)

    def test_parse_failed_line(self):
        line = "Oct 27 10:02:01 server1 sshd[1240]: Failed password for invalid user admin from 203.0.113.45 port 41201 ssh2"
        event = self.analyzer.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event.status, "FAILED")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.ip, "203.0.113.45")
        self.assertTrue(event.is_invalid_user)

    def test_threat_detection_threshold(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write(SAMPLE_LOG)
            tmp_path = tmp.name

        try:
            report = self.analyzer.analyze_file(tmp_path)
            self.assertEqual(report.total_events, 7)
            self.assertEqual(report.successful_logins, 2)
            self.assertEqual(report.failed_logins, 5)
            self.assertEqual(report.unique_attacker_ips, 1)
            self.assertIn("203.0.113.45", report.flagged_ips)
            self.assertEqual(report.flagged_ips["203.0.113.45"]["fail_count"], 5)
        finally:
            os.remove(tmp_path)

    def test_markdown_rendering(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as tmp:
            tmp.write(SAMPLE_LOG)
            tmp_path = tmp.name

        try:
            report = self.analyzer.analyze_file(tmp_path)
            md = self.analyzer.render_markdown(report)
            self.assertIn("Security Incident & Threat Analysis Report", md)
            self.assertIn("203.0.113.45", md)
        finally:
            os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
