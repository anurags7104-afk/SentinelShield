"""Unit tests for SentinelShield. Run with: python test_sentinelshield.py"""

import tempfile
import unittest
from pathlib import Path

from modules import analyzer
from modules.inspector import inspect, normalize
from modules.logger import EventLogger
from modules.ratelimiter import RateLimiter
from modules.waf import SentinelShield


def req(path="/", query="", body="", headers=None, ip="198.51.100.1", ts=0.0, method="GET"):
    return {"ip": ip, "method": method, "path": path, "query": query,
            "body": body, "headers": headers or {}, "ts": ts}


class InspectorTests(unittest.TestCase):
    def verdict(self, **kw):
        return inspect(req(**kw))

    def test_clean_request_is_allowed(self):
        r = self.verdict(path="/products", query="id=42&sort=price")
        self.assertEqual((r["verdict"], r["score"]), ("ALLOW", 0))

    def test_sql_tautology_blocked(self):
        r = self.verdict(query="id=1' OR '1'='1")
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertIn("SQLI-002", [m["rule_id"] for m in r["matches"]])

    def test_union_select_with_comments_blocked(self):
        self.assertEqual(self.verdict(query="q=1 UNION/**/SELECT/**/null")["verdict"], "BLOCK")

    def test_xss_script_tag_blocked(self):
        r = self.verdict(query="q=<script>alert(1)</script>")
        self.assertEqual(r["verdict"], "BLOCK")
        self.assertEqual({m["category"] for m in r["matches"]}, {"xss"})

    def test_xss_in_header_found(self):
        r = self.verdict(headers={"Referer": "<script>alert(1)</script>"})
        self.assertEqual(r["matches"][0]["location"], "header:Referer")

    def test_lfi_and_traversal_blocked(self):
        r = self.verdict(query="file=../../../../windows/win.ini")
        self.assertEqual({m["category"] for m in r["matches"]}, {"lfi", "traversal"})

    def test_command_injection_blocked(self):
        self.assertEqual(self.verdict(query="host=8.8.8.8 && whoami")["verdict"], "BLOCK")

    def test_double_encoding_decoded(self):
        self.assertEqual(normalize("%2527%2520OR"), "' OR")
        self.assertEqual(self.verdict(query="id=1%2527%2520OR%2520%25271%2527%253D%25271")["verdict"], "BLOCK")

    def test_body_is_inspected(self):
        self.assertEqual(self.verdict(method="POST", body="username=admin'--&password=x")["verdict"], "BLOCK")

    def test_scanner_user_agent_is_only_suspicious(self):
        r = self.verdict(headers={"User-Agent": "sqlmap/1.7"})
        self.assertEqual((r["verdict"], r["score"]), ("SUSPICIOUS", 3))

    def test_score_is_sum_of_distinct_rules(self):
        r = self.verdict(query="x=<script>1</script><script>2</script>")   # same rule twice counts once
        self.assertEqual(sum(m["weight"] for m in r["matches"]), r["score"])


class RateLimiterTests(unittest.TestCase):
    def test_limit_is_exact(self):
        rl = RateLimiter(limit=10, window=10)
        results = [rl.over_limit("1.1.1.1", i * 0.1) for i in range(12)]
        self.assertEqual(results, [False] * 10 + [True] * 2)

    def test_window_slides(self):
        rl = RateLimiter(limit=2, window=10)
        rl.over_limit("a", 0); rl.over_limit("a", 1)
        self.assertTrue(rl.over_limit("a", 2))
        self.assertFalse(rl.over_limit("a", 20))     # old hits have expired

    def test_ban_after_strikes_and_expiry(self):
        rl = RateLimiter(ban_after={"rate": 2, "attack": 3}, ban_seconds=60)
        self.assertFalse(rl.add_strike("a", "rate", 0))
        self.assertTrue(rl.add_strike("a", "rate", 1))
        self.assertTrue(rl.is_banned("a", 30))
        self.assertFalse(rl.is_banned("a", 61))


class WafTests(unittest.TestCase):
    def test_brute_force_sequence(self):
        waf = SentinelShield(RateLimiter(limit=10, window=10))
        actions = [waf.handle(req("/login", body=f"u=a&p={i}", ts=i * 0.2, ip="9.9.9.9", method="POST"))["action"]
                   for i in range(25)]
        self.assertEqual(actions, ["ALLOW"] * 10 + ["RATE_LIMIT"] * 5 + ["BLOCK_IP"] * 10)

    def test_repeat_attacker_banned_after_three_blocks(self):
        waf = SentinelShield()
        actions = [waf.handle(req(query="id=1' OR '1'='1", ip="7.7.7.7", ts=i))["action"] for i in range(5)]
        self.assertEqual(actions, ["BLOCK"] * 3 + ["BLOCK_IP"] * 2)

    def test_status_codes(self):
        waf = SentinelShield()
        self.assertEqual(waf.handle(req())["status"], 200)
        self.assertEqual(waf.handle(req(query="q=<script>x</script>", ip="2.2.2.2"))["status"], 403)

    def test_logger_writes_every_request(self):
        with tempfile.TemporaryDirectory() as d:
            log = EventLogger(Path(d) / "log.jsonl")
            waf = SentinelShield(logger=log)
            waf.handle(req())
            waf.handle(req(query="q=/etc/passwd", ip="3.3.3.3"))
            rows = log.read()
            self.assertEqual([r["action"] for r in rows], ["ALLOW", "BLOCK"])
            self.assertEqual(rows[1]["categories"], ["lfi"])


class AnalyzerTests(unittest.TestCase):
    def test_evaluate_counts(self):
        results = [
            {"id": "1", "label": "malicious", "category": "sqli", "action": "BLOCK"},
            {"id": "2", "label": "malicious", "category": "xss", "action": "ALLOW"},
            {"id": "3", "label": "benign", "category": "normal", "action": "BLOCK"},
            {"id": "4", "label": "benign", "category": "normal", "action": "ALLOW"},
            {"id": "5", "label": "benign", "category": "normal", "action": "ALLOW"},
        ]
        e = analyzer.evaluate(results)
        self.assertEqual((e["tp"], e["fn"], e["fp"], e["tn"]), (1, 1, 1, 2))
        self.assertEqual(e["accuracy"], 60.0)
        self.assertEqual(e["recall"], 50.0)
        self.assertEqual(e["precision"], 50.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
