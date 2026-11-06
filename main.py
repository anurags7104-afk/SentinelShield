import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from modules import analyzer, dashboard, reporter
from modules.inspector import inspect
from modules.logger import EventLogger
from modules.ratelimiter import RateLimiter
from modules.waf import SentinelShield
import scenarios

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "output"


def do_demo():
    OUT.mkdir(exist_ok=True)
    logger = EventLogger(OUT / "waf_log.jsonl")
    logger.reset()
    waf = SentinelShield(RateLimiter(limit=10, window=10.0), logger)

    requests = scenarios.all_requests()
    json.dump([{k: v for k, v in r.items()} for r in requests],
              open(OUT / "test_requests.json", "w", encoding="utf-8"), indent=2)

    print(f"[*] Sending {len(requests)} labeled requests through SentinelShield...\n")
    results = []
    for r in requests:
        d = waf.handle(r)
        url = r["path"] + (f"?{r['query']}" if r["query"] else "")
        results.append({"id": r["id"], "label": r["label"], "category": r["category"],
                        "action": d["action"], "method": r["method"], "url": url,
                        "note": r.get("note", ""), "score": d["score"],
                        "rules": d["rule_ids"]})
        cats = ",".join(d["categories"]) or "-"
        print(f"[{d['action']:<10}] {r['id']:<5} {r['method']:<4} {url[:58]:<58} score={d['score']:<2} {cats}")

    entries = logger.read()
    summary = analyzer.summarize(entries, waf.limiter.ban_events)
    evaluation = analyzer.evaluate(results)

    logger.export_csv(OUT / "waf_log.csv")
    json.dump({"summary": summary, "evaluation": evaluation},
              open(OUT / "evaluation.json", "w", encoding="utf-8"), indent=2)
    (OUT / "sentinel_report.md").write_text(reporter.build_report(summary, evaluation), encoding="utf-8")
    page = dashboard.render(summary, evaluation, entries, standalone=True)
    (OUT / "dashboard.html").write_text(page, encoding="utf-8")
    (ROOT / "index.html").write_text(page, encoding="utf-8")

    print("\n[+] Requests: {total_requests}, flagged: {malicious_detected}, blocked: {blocked}".format(**summary))
    print("[+] By action: " + ", ".join(f"{k}={v}" for k, v in sorted(summary["by_action"].items())))
    print("[+] By category: " + ", ".join(f"{k}={v}" for k, v in summary["by_category"].items()))
    e = evaluation
    print(f"[+] Accuracy {e['accuracy']}%  (TP={e['tp']} TN={e['tn']} FP={e['fp']} FN={e['fn']})")
    print(f"[+] Banned IPs: {', '.join(b['ip'] for b in summary['ban_events']) or 'none'}")
    print(f"[+] Log:       {OUT / 'waf_log.jsonl'}")
    print(f"[+] Report:    {OUT / 'sentinel_report.md'}")
    print(f"[+] Dashboard: {ROOT / 'index.html'}")


def do_inspect(url):
    parts = urlsplit(url)
    result = inspect({"path": parts.path, "query": parts.query, "headers": {}, "body": ""})
    print(f"Verdict: {result['verdict']}   score: {result['score']}")
    for m in result["matches"]:
        print(f"  {m['rule_id']}  {m['name']}  ({m['severity']})  in {m['location']}: {m['snippet']!r}")
    if not result["matches"]:
        print("  no signature matched")


def do_serve(port):
    OUT.mkdir(exist_ok=True)
    logger = EventLogger(OUT / "live_log.jsonl")
    waf = SentinelShield(RateLimiter(limit=10, window=10.0), logger)

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            parts = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
            # X-Forwarded-For lets you pretend to be different clients while testing with curl
            ip = self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
            req = {"ip": ip, "method": self.command, "path": parts.path, "query": parts.query,
                   "headers": dict(self.headers), "body": body, "ts": time.time()}
            d = waf.handle(req)
            print(f"[{d['action']:<10}] {ip:<15} {self.command} {self.path[:60]}  score={d['score']}")
            payload = json.dumps({"action": d["action"], "status": d["status"], "score": d["score"],
                                  "reason": d["reason"], "rules": d["rule_ids"]}, indent=2).encode()
            self.send_response(d["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = _handle

        def log_message(self, *args):
            pass

    print(f"[*] SentinelShield test server on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    print("[*] Events are logged to output/live_log.jsonl")
    try:
        HTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
    elif args[0] == "demo":
        do_demo()
    elif args[0] == "inspect" and len(args) > 1:
        do_inspect(args[1])
    elif args[0] == "serve":
        do_serve(int(args[1]) if len(args) > 1 else 8080)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
