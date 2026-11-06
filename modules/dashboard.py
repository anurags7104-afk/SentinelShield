"""
dashboard.py
------------
Builds a self-contained HTML dashboard (no external libraries) from the
analysis summary and the evaluation. `python main.py demo` writes it to
output/dashboard.html and to index.html, so it can be hosted on GitHub Pages.
"""

import html as _html

CSS = """
:root{--bg:#F2F4F6;--surface:#fff;--surface2:#E8ECF0;--border:#D3D9E0;--ink:#16202A;--dim:#5A6775;--accent:#1B6A8F;
--bad:#B3342B;--bad-s:#F5DEDB;--warn:#A66A12;--warn-s:#F4E7D0;--good:#2E7D5B;--good-s:#DCEEE5;--mono:ui-monospace,'Cascadia Mono',Consolas,monospace;--sans:system-ui,'Segoe UI',Arial,sans-serif}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#10171D;--surface:#18222B;--surface2:#212D38;--border:#2F3E4B;--ink:#E8EEF3;--dim:#93A3B1;--accent:#6DB3E0;--bad:#EE8579;--bad-s:#3C2522;--warn:#E3B060;--warn-s:#38301B;--good:#6FC79C;--good-s:#1D3328;color-scheme:dark}}
:root[data-theme="dark"]{--bg:#10171D;--surface:#18222B;--surface2:#212D38;--border:#2F3E4B;--ink:#E8EEF3;--dim:#93A3B1;--accent:#6DB3E0;--bad:#EE8579;--bad-s:#3C2522;--warn:#E3B060;--warn-s:#38301B;--good:#6FC79C;--good-s:#1D3328;color-scheme:dark}
*{box-sizing:border-box}
html{background:var(--bg)}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);margin:0;padding-left:max(16px,env(safe-area-inset-left,0px));padding-right:max(16px,env(safe-area-inset-right,0px))}
.wrap{max-width:1080px;margin:0 auto;padding-block:32px 56px;display:flex;flex-direction:column;gap:26px}
header{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:flex-end;gap:12px;border-bottom:1px solid var(--border);padding-bottom:18px}
h1{font-size:28px;margin:0 0 6px;text-wrap:balance}
header p{margin:0;color:var(--dim);font-size:14px;max-width:62ch}
.tag{font:12px var(--mono);background:var(--surface2);border:1px solid var(--border);color:var(--dim);padding:6px 10px;border-radius:5px}
.rail{display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:8px;overflow:hidden}
.stat{background:var(--surface);padding:16px;min-width:0}
.stat .l{font-size:11px;text-transform:uppercase;letter-spacing:.07em;color:var(--dim);margin-bottom:6px}
.stat .v{font-size:28px;font-weight:600;font-variant-numeric:tabular-nums}
.stat .s{font-size:12px;color:var(--dim);margin-top:2px}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.09em;color:var(--dim);margin:0 0 12px}
.two{display:grid;grid-template-columns:1fr 1fr;gap:20px}.two>*{min-width:0}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:18px}
.row{display:grid;grid-template-columns:96px 1fr 48px;gap:10px;align-items:center;margin-bottom:9px;font-size:13px}
.row .n{font-family:var(--mono);text-align:right}
.track{background:var(--surface2);border-radius:3px;height:12px;overflow:hidden}
.fill{height:100%;background:var(--accent)}
.fill.bad{background:var(--bad)}.fill.warn{background:var(--warn)}.fill.good{background:var(--good)}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--dim);background:var(--surface2);font-weight:600;white-space:nowrap}
tr:last-child td{border-bottom:0}
td.m{font-family:var(--mono);font-size:12px;word-break:break-all}
.pill{font-size:11px;font-weight:600;padding:3px 9px;border-radius:99px;white-space:nowrap}
.pill.BLOCK,.pill.BLOCK_IP{background:var(--bad-s);color:var(--bad)}.pill.RATE_LIMIT{background:var(--warn-s);color:var(--warn)}
.pill.SUSPICIOUS{background:var(--warn-s);color:var(--warn)}.pill.ALLOW{background:var(--good-s);color:var(--good)}
.note{font-size:12px;color:var(--dim);margin:12px 0 0;line-height:1.5}
footer{border-top:1px solid var(--border);padding-top:14px;font-size:12px;color:var(--dim);display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
@media(max-width:760px){.rail{grid-template-columns:repeat(2,1fr)}.two{grid-template-columns:1fr}}
"""


def _e(s):
    return _html.escape(str(s))


def _bars(items, cls="", total=None):
    if not items:
        return "<p class='note'>No data.</p>"
    top = total or max(v for _, v in items) or 1
    return "".join(
        f"<div class='row'><span>{_e(k)}</span><div class='track'><div class='fill {cls}' style='width:{v / top * 100:.0f}%'></div></div><span class='n'>{v}</span></div>"
        for k, v in items)


def render(summary: dict, evaluation: dict, entries: list, standalone: bool = True) -> str:
    sm, ev = summary, evaluation
    recent = [e for e in entries if e["action"] != "ALLOW"][:14]
    actions = sorted(sm["by_action"].items(), key=lambda kv: -kv[1])
    cat_rows = list(sm["by_category"].items())
    det_rows = [(c, v["detected"]) for c, v in ev["per_category"].items()]

    ip_rows = "".join(
        f"<tr><td class='m'>{_e(r['ip'])}</td><td>{r['flagged']}</td><td>{_e(', '.join(f'{k} {v}' for k, v in r['actions'].items()))}</td></tr>"
        for r in sm["repeat_ips"]) or "<tr><td colspan='3'>No repeat offenders.</td></tr>"
    log_rows = "".join(
        f"<tr><td class='m'>{_e(e['timestamp'][11:19])}</td><td class='m'>{_e(e['ip'])}</td>"
        f"<td class='m'>{_e(e['method'])} {_e(e['url'][:70])}</td>"
        f"<td><span class='pill {e['action']}'>{e['action']}</span></td>"
        f"<td class='m'>{_e(', '.join(e['categories']) or '-')}</td></tr>" for e in recent)
    fp = "".join(f"<li>{_e(r['id'])}: {_e(r['method'])} {_e(r['url'][:70])}</li>" for r in ev["false_positives"]) or "<li>None</li>"
    fn = "".join(f"<li>{_e(r['id'])}: {_e(r['method'])} {_e(r['url'][:70])}</li>" for r in ev["false_negatives"]) or "<li>None</li>"

    body = f"""
<div class="wrap">
<header><div><h1>SentinelShield Dashboard</h1><p>Results of a labeled test run: normal traffic, web attacks, a brute-force burst and a repeat attacker, all inspected by the rule engine and the rate limiter. IPs are from reserved documentation ranges.</p></div><span class="tag">Python · rule-based · Anurag Singh</span></header>
<div class="rail">
<div class="stat"><div class="l">Requests</div><div class="v">{sm['total_requests']}</div><div class="s">{sm['unique_ips']} source IPs</div></div>
<div class="stat"><div class="l">Flagged</div><div class="v" style="color:var(--bad)">{sm['malicious_detected']}</div><div class="s">{sm['blocked']} blocked</div></div>
<div class="stat"><div class="l">Accuracy</div><div class="v">{ev['accuracy']}%</div><div class="s">{ev['tp'] + ev['tn']} of {ev['total']} correct</div></div>
<div class="stat"><div class="l">False positives</div><div class="v">{ev['fp']}</div><div class="s">benign flagged</div></div>
<div class="stat"><div class="l">False negatives</div><div class="v">{ev['fn']}</div><div class="s">attacks missed</div></div>
</div>
<div class="two">
<section class="panel"><h2>What happened to each request</h2>{_bars(actions)}<p class="note">ALLOW passes, SUSPICIOUS passes but is logged, BLOCK and BLOCK_IP return 403, RATE_LIMIT returns 429.</p></section>
<section class="panel"><h2>Flagged requests by attack category</h2>{_bars(cat_rows, 'bad')}</section>
</div>
<div class="two">
<section class="panel"><h2>Attacks detected per category</h2>{_bars(det_rows, 'good')}<p class="note">Sent per category: {_e(', '.join(f"{c} {v['total']}" for c, v in ev['per_category'].items()))}.</p></section>
<section class="panel"><h2>Repeatedly flagged IPs</h2><div class="tw"><table><tr><th>IP</th><th>Flagged</th><th>Actions</th></tr>{ip_rows}</table></div><p class="note">An IP is banned for 300 seconds after 3 blocked attacks or 5 rate-limit violations.</p></section>
</div>
<section><h2>Recent flagged requests</h2><div class="panel" style="padding:0"><div class="tw"><table><tr><th>Time (UTC)</th><th>IP</th><th>Request</th><th>Action</th><th>Category</th></tr>{log_rows}</table></div></div></section>
<div class="two">
<section class="panel"><h2>False positives</h2><ul class="note" style="margin:0;padding-left:18px">{fp}</ul></section>
<section class="panel"><h2>False negatives</h2><ul class="note" style="margin:0;padding-left:18px">{fn}</ul></section>
</div>
<footer><span>Dashboard shows output of a simulated test run, not live traffic.</span><span>Run it yourself: <span style="font-family:var(--mono)">python main.py demo</span></span></footer>
</div>"""

    if standalone:
        return ("<!doctype html>\n<html lang='en'><head><meta charset='utf-8'>"
                "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                "<title>SentinelShield Dashboard</title>"
                f"<style>{CSS}</style></head><body>{body}</body></html>\n")
    return ("<title>SentinelShield Dashboard</title>\n"
            "<meta name=\"claude:viewport-fit-sides\" content=\"cover\">\n"
            f"<style>{CSS}</style>\n{body}\n")
