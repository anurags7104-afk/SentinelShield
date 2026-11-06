"""
rules.py
--------
Attack signature definitions for SentinelShield.

Each rule is one known attack technique written as a regular expression.
A rule has a severity, and each severity carries a weight. The inspector adds
up the weights of the distinct rules that match a request to get its score.

    high   = 5   enough on its own to block the request
    medium = 3   suspicious on its own, blocks only when combined with others
    low    = 1   informational
"""

import re
from dataclasses import dataclass

WEIGHTS = {"high": 5, "medium": 3, "low": 1}


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: str
    name: str
    severity: str
    regex: "re.Pattern"

    @property
    def weight(self) -> int:
        return WEIGHTS[self.severity]


def _rule(rule_id, category, name, severity, pattern):
    return Rule(rule_id, category, name, severity, re.compile(pattern, re.IGNORECASE))


RULES = [
    # --- SQL injection ---------------------------------------------------
    _rule("SQLI-001", "sqli", "UNION SELECT", "high",
          r"\bunion\b(?:\s|/\*.*?\*/)+(?:all\s+)?select\b"),
    _rule("SQLI-002", "sqli", "Boolean tautology (OR 1=1)", "high",
          r"\b(?:or|and)\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+"),
    _rule("SQLI-003", "sqli", "Quote followed by SQL comment", "high",
          r"['\"]\s*(?:--|#|/\*)"),
    _rule("SQLI-004", "sqli", "Stacked destructive statement", "high",
          r";\s*(?:drop|delete|insert|update|alter|truncate)\b"),
    _rule("SQLI-005", "sqli", "Time-based function (SLEEP)", "high",
          r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
    _rule("SQLI-006", "sqli", "information_schema access", "medium",
          r"\binformation_schema\b"),

    # --- Cross-site scripting -------------------------------------------
    _rule("XSS-001", "xss", "Script tag", "high",
          r"<\s*script\b"),
    _rule("XSS-002", "xss", "Inline event handler", "high",
          r"<[^>]*\bon\w+\s*="),
    _rule("XSS-003", "xss", "javascript: URI", "medium",
          r"javascript\s*:"),
    _rule("XSS-004", "xss", "Dangerous HTML tag", "medium",
          r"<\s*(?:iframe|object|embed|svg)\b"),
    _rule("XSS-005", "xss", "document.cookie / location access", "medium",
          r"document\.(?:cookie|location|write)"),

    # --- Local file inclusion -------------------------------------------
    _rule("LFI-001", "lfi", "Sensitive system file", "high",
          r"/etc/(?:passwd|shadow|hosts)|boot\.ini|win\.ini|/proc/self/environ"),
    _rule("LFI-002", "lfi", "PHP / file stream wrapper", "high",
          r"\b(?:php|file|data|expect|zip|phar)://"),

    # --- Directory traversal --------------------------------------------
    _rule("TRAV-001", "traversal", "Parent directory sequence", "high",
          r"\.\.[/\\]"),

    # --- Command injection ----------------------------------------------
    _rule("CMDI-001", "cmdi", "Shell operator followed by a command", "high",
          r"(?:;|\|\||&&|\||`)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|netcat|bash|sh|cmd|powershell|ping|rm)\b"),
    _rule("CMDI-002", "cmdi", "Command substitution $( )", "high",
          r"\$\(\s*\w+"),
    _rule("CMDI-003", "cmdi", "Shell binary path", "high",
          r"/bin/(?:ba)?sh\b|\bcmd\.exe\b"),

    # --- Automated scanners ---------------------------------------------
    _rule("SCAN-001", "scanner", "Known scanner user agent", "medium",
          r"\b(?:sqlmap|nikto|nmap|acunetix|dirbuster|masscan)\b"),
]

CATEGORIES = ["sqli", "xss", "lfi", "traversal", "cmdi", "scanner"]
