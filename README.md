# SentinelShield: Intrusion Detection and Web Protection System

A lightweight, rule-based Web Application Firewall (WAF) and intrusion detection toolkit in Python.
It inspects HTTP requests, detects web attacks with signatures, watches for abusive traffic with a rate
limiter, logs every decision and builds a report and a dashboard. Standard library only, Python 3.9+.

## How it maps to the project workflow

| Project step | Where it is implemented |
|---|---|
| Request processing (URL, parameters, headers, body) | `modules/inspector.py` |
| Rule definitions (SQLi, XSS, LFI, traversal, command injection) | `modules/rules.py` |
| Traffic monitoring and rate limiting | `modules/ratelimiter.py` |
| Alert decisions (allow, block, ban) | `modules/waf.py` |
| Logging | `modules/logger.py` writes `output/waf_log.jsonl` and `.csv` |
| Log analysis and accuracy evaluation | `modules/analyzer.py` |
| Report | `modules/reporter.py` writes `output/sentinel_report.md` |
| Dashboard | `modules/dashboard.py` writes `index.html` |
| Labeled test traffic | `scenarios.py` |

## Usage

```
python main.py demo               # run 70 labeled requests, write the log, report and dashboard
python main.py inspect "/search?q=<script>alert(1)</script>"
python main.py serve 8080         # test web app protected by the WAF
python test_sentinelshield.py     # 19 unit tests
```

With `serve` running, attack it from a second terminal (use `curl.exe` in PowerShell):

```
curl.exe "http://127.0.0.1:8080/products?id=42"                                  # 200 allowed
curl.exe "http://127.0.0.1:8080/products?id=1%27%20OR%20%271%27%3D%271"          # 403 blocked
curl.exe -H "X-Forwarded-For: 203.0.113.5" "http://127.0.0.1:8080/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

## Decisions

| Action | Status | When |
|---|---|---|
| ALLOW | 200 | score 0 |
| SUSPICIOUS | 200 | score 1 to 4: allowed but logged |
| BLOCK | 403 | score 5 or more (a high rule is 5, a medium rule 3, scores add up) |
| RATE_LIMIT | 429 | more than 10 requests from one IP in 10 seconds |
| BLOCK_IP | 403 | IP banned for 300 s after 3 blocked attacks or 5 rate-limit violations |

## Notes

All demo IPs use reserved documentation ranges. The test set includes two benign requests that look like
attacks and two attacks that avoid the signatures, so the report shows real false positives and false
negatives. Signature matching cannot catch everything: this is a learning tool, not a replacement for a
production WAF.
