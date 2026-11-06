# SentinelShield: Detection Report

Generated: 2026-11-06 08:54 UTC  
Mode: simulation  
Requests processed: **70** from 42 source IPs

## 1. Outcome of every request
| Action | Count |
|---|---|
| ALLOW | 24 |
| BLOCK | 27 |
| BLOCK_IP | 12 |
| RATE_LIMIT | 5 |
| SUSPICIOUS | 2 |

Flagged (anything except ALLOW): **46**. Blocked outright (BLOCK, RATE_LIMIT, BLOCK_IP): **44**.

## 2. Distribution by attack category
| Category | Flagged requests |
|---|---|
| banned_ip | 12 |
| sqli | 9 |
| lfi | 8 |
| xss | 7 |
| rate_limit | 5 |
| traversal | 4 |
| cmdi | 4 |
| scanner | 2 |

## 3. Repeatedly flagged IP addresses
| IP | Flagged requests | Actions |
|---|---|---|
| 203.0.113.250 | 15 | RATE_LIMIT=5, BLOCK_IP=10 |
| 203.0.113.99 | 5 | BLOCK=3, BLOCK_IP=2 |

Temporary bans issued:

| IP | Reason | Strikes |
|---|---|---|
| 203.0.113.250 | rate | 5 |
| 203.0.113.99 | attack | 3 |

## 4. Detection accuracy on labeled traffic
| Metric | Value |
|---|---|
| Total labeled requests | 70 |
| Malicious requests sent | 46 |
| Benign requests sent | 24 |
| True positives | 44 |
| True negatives | 22 |
| False positives | 2 |
| False negatives | 2 |
| Accuracy | 94.3% |
| Precision | 95.7% |
| Recall (detection rate) | 95.7% |

| Attack category | Sent | Detected |
|---|---|---|
| bruteforce | 15 | 15 |
| cmdi | 5 | 5 |
| lfi | 4 | 4 |
| scanner | 2 | 2 |
| sqli | 9 | 8 |
| traversal | 4 | 4 |
| xss | 7 | 6 |

## 5. False positives
- **B13**: GET /search?q=trade+union+select+committee+elections was flagged as BLOCK. legitimate text that contains the words 'union select'
- **B14**: POST /comment was flagged as BLOCK. legitimate text that mentions a script tag

## 6. False negatives
- **M25**: GET /search?q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg== was allowed. base64 of a script tag
- **M26**: GET /products?id=1 AND ASCII(SUBSTRING(@@version,1,1))>50 was allowed. blind SQL injection with no tautology

## 7. Suggested rule improvements
- Decode base64 values and re-inspect them to catch encoded script tags.
- Add rules for blind SQL injection functions such as ASCII, SUBSTRING and @@version.
- Lower the weight of single signatures in free-text fields (search, comments), or require two matching signals before blocking.
- Add an allow-list for known-safe endpoints that legitimately accept code-like text.
- Tune the rate limit per endpoint: a login page needs a much lower limit than a static page.
