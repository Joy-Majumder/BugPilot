"""
Burp Suite-style Repeater Module
Manual request editing, replay, and response analysis
"""
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from enum import Enum
import httpx
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class TabType(Enum):
    RAW = "raw"
    PARAMS = "params"
    HEADERS = "headers"
    BODY = "body"
    RENDERED = "rendered"


@dataclass
class RepeaterRequest:
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    params: Dict[str, str] = field(default_factory=dict)
    
    def to_raw(self) -> str:
        """Convert to raw HTTP request format"""
        parsed = urlparse(self.url)
        path = parsed.path or '/'
        if parsed.query:
            path += '?' + parsed.query
        
        lines = [f"{self.method} {path} HTTP/1.1"]
        
        # Host header
        if 'Host' not in self.headers:
            self.headers['Host'] = parsed.netloc
        
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        
        lines.append('')
        if self.body:
            lines.append(self.body)
        
        return '\n'.join(lines)
    
    @classmethod
    def from_raw(cls, raw: str) -> 'RepeaterRequest':
        """Parse raw HTTP request"""
        lines = raw.split('\n')
        if not lines:
            raise ValueError("Empty request")
        
        request_line = lines[0].strip()
        parts = request_line.split(' ')
        if len(parts) != 3:
            raise ValueError(f"Invalid request line: {request_line}")
        method, path, version = parts
        
        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line.strip() == '':
                body_start = i + 1
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
        
        host = headers.get('Host', '')
        scheme = 'http'
        if 'X-Forwarded-Proto' in headers:
            scheme = headers['X-Forwarded-Proto']
        elif 'https' in host:
            scheme = 'https'
        
        url = f"{scheme}://{host}{path}"
        
        # Parse query params
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        
        return cls(
            method=method,
            url=url,
            headers=headers,
            body=body,
            params=params
        )
    
    def update_url_from_params(self):
        """Update URL with current params"""
        parsed = urlparse(self.url)
        query = urlencode(self.params, doseq=True)
        self.url = urlunparse(parsed._replace(query=query))
    
    def add_header(self, key: str, value: str):
        self.headers[key] = value
    
    def remove_header(self, key: str):
        self.headers.pop(key, None)
    
    def set_body_json(self, data: dict):
        self.body = json.dumps(data, indent=2)
        self.headers['Content-Type'] = 'application/json'
    
    def set_body_form(self, data: dict):
        self.body = urlencode(data, doseq=True)
        self.headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
    def set_body_raw(self, body: str, content_type: str = 'text/plain'):
        self.body = body
        self.headers['Content-Type'] = content_type


@dataclass
class RepeaterResponse:
    status_code: int
    status_text: str
    headers: Dict[str, str]
    body: str
    response_time: float
    response_length: int
    timestamp: float = field(default_factory=time.time)
    request: Optional[RepeaterRequest] = None
    
    def to_raw(self) -> str:
        lines = [f"HTTP/1.1 {self.status_code} {self.status_text}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append('')
        lines.append(self.body)
        return '\n'.join(lines)
    
    def get_content_type(self) -> str:
        return self.headers.get('Content-Type', '').lower()
    
    def is_json(self) -> bool:
        return 'application/json' in self.get_content_type()
    
    def is_html(self) -> bool:
        return 'text/html' in self.get_content_type()
    
    def is_xml(self) -> bool:
        return 'xml' in self.get_content_type()
    
    def json(self) -> dict:
        try:
            return json.loads(self.body)
        except:
            return {}
    
    def get_cookies(self) -> Dict[str, str]:
        cookies = {}
        for header in self.headers.get('Set-Cookie', '').split(','):
            if '=' in header:
                k, v = header.split('=', 1)
                cookies[k.strip()] = v.split(';')[0].strip()
        return cookies


@dataclass
class RepeaterHistoryEntry:
    request: RepeaterRequest
    response: Optional[RepeaterResponse]
    timestamp: float = field(default_factory=time.time)
    note: str = ""


class Repeater:
    def __init__(self, http_client: httpx.AsyncClient = None):
        self.http_client = http_client
        self.history: List[RepeaterHistoryEntry] = []
        self.current_request: Optional[RepeaterRequest] = None
        self.current_response: Optional[RepeaterResponse] = None
    
    def set_http_client(self, client: httpx.AsyncClient):
        self.http_client = client
    
    def new_request(self, method: str = "GET", url: str = "") -> RepeaterRequest:
        self.current_request = RepeaterRequest(method=method, url=url)
        return self.current_request
    
    def load_request(self, request: RepeaterRequest):
        self.current_request = request
    
    def load_from_raw(self, raw: str) -> RepeaterRequest:
        self.current_request = RepeaterRequest.from_raw(raw)
        return self.current_request
    
    async def send(self, request: Optional[RepeaterRequest] = None) -> RepeaterResponse:
        req = request or self.current_request
        if not req:
            raise ValueError("No request to send")
        
        if not self.http_client:
            raise ValueError("No HTTP client configured")
        
        self.current_request = req
        start = time.time()
        
        try:
            kwargs = {"timeout": 30.0, "follow_redirects": True}
            
            if req.body:
                content_type = req.headers.get('Content-Type', '').lower()
                if 'application/json' in content_type:
                    kwargs['json'] = json.loads(req.body)
                else:
                    kwargs['content'] = req.body
                kwargs['headers'] = req.headers
            else:
                kwargs['headers'] = req.headers
            
            if req.method == "GET":
                resp = await self.http_client.get(req.url, **kwargs)
            elif req.method == "POST":
                resp = await self.http_client.post(req.url, **kwargs)
            elif req.method == "PUT":
                resp = await self.http_client.put(req.url, **kwargs)
            elif req.method == "DELETE":
                resp = await self.http_client.delete(req.url, **kwargs)
            elif req.method == "PATCH":
                resp = await self.http_client.patch(req.url, **kwargs)
            elif req.method == "HEAD":
                resp = await self.http_client.head(req.url, **kwargs)
            elif req.method == "OPTIONS":
                resp = await self.http_client.options(req.url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {req.method}")
            
            response_time = time.time() - start
            
            response = RepeaterResponse(
                status_code=resp.status_code,
                status_text=resp.reason_phrase or "",
                headers=dict(resp.headers),
                body=resp.text,
                response_time=response_time,
                response_length=len(resp.content),
                request=req
            )
            
            self.current_response = response
            self.history.append(RepeaterHistoryEntry(
                request=req,
                response=response
            ))
            
            return response
            
        except Exception as e:
            response_time = time.time() - start
            error_response = RepeaterResponse(
                status_code=0,
                status_text="Error",
                headers={},
                body=str(e),
                response_time=response_time,
                response_length=0,
                request=req
            )
            self.current_response = error_response
            self.history.append(RepeaterHistoryEntry(
                request=req,
                response=error_response
            ))
            return error_response
    
    def get_history(self) -> List[RepeaterHistoryEntry]:
        return self.history
    
    def clear_history(self):
        self.history.clear()
    
    def compare_responses(self, idx1: int, idx2: int) -> Dict[str, Any]:
        """Compare two responses from history"""
        if idx1 >= len(self.history) or idx2 >= len(self.history):
            return {"error": "Invalid history indices"}
        
        r1 = self.history[idx1].response
        r2 = self.history[idx2].response
        
        if not r1 or not r2:
            return {"error": "One or both responses missing"}
        
        return {
            "status_diff": r1.status_code != r2.status_code,
            "length_diff": r2.response_length - r1.response_length,
            "time_diff": r2.response_time - r1.response_time,
            "headers_changed": self._diff_headers(r1.headers, r2.headers),
            "body_similarity": self._similarity(r1.body, r2.body)
        }
    
    def _diff_headers(self, h1: Dict, h2: Dict) -> Dict:
        ignore = {'date', 'server', 'set-cookie', 'expires', 'cache-control', 'etag', 'last-modified'}
        all_keys = set(h1.keys()) | set(h2.keys())
        changed = {}
        for k in all_keys:
            if k.lower() in ignore:
                continue
            if h1.get(k) != h2.get(k):
                changed[k] = {"before": h1.get(k), "after": h2.get(k)}
        return changed
    
    def _similarity(self, s1: str, s2: str) -> float:
        """Simple similarity ratio"""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        # Simple character-level similarity
        len1, len2 = len(s1), len(s2)
        max_len = max(len1, len2)
        if max_len == 0:
            return 1.0
        # Count matching characters at same positions
        matches = sum(c1 == c2 for c1, c2 in zip(s1, s2))
        return matches / max_len
    
    def search_history(self, query: str, in_body: bool = True, in_headers: bool = True) -> List[int]:
        """Search history for query"""
        results = []
        for i, entry in enumerate(self.history):
            if not entry.response:
                continue
            if in_body and query.lower() in entry.response.body.lower():
                results.append(i)
            if in_headers:
                for v in entry.response.headers.values():
                    if query.lower() in v.lower():
                        results.append(i)
                        break
        return results


# Utility functions for common operations
def add_auth_header(request: RepeaterRequest, token: str, auth_type: str = "Bearer"):
    """Add authorization header"""
    request.headers['Authorization'] = f"{auth_type} {token}"

def add_cookie_header(request: RepeaterRequest, cookies: Dict[str, str]):
    """Add cookies to request"""
    cookie_str = '; '.join(f"{k}={v}" for k, v in cookies.items())
    if cookie_str:
        request.headers['Cookie'] = cookie_str

def follow_redirects(response: RepeaterResponse, request: RepeaterRequest, max_redirects: int = 5) -> List[RepeaterResponse]:
    """Extract redirect chain"""
    redirects = []
    location = response.headers.get('Location') or response.headers.get('location')
    while location and len(redirects) < max_redirects:
        # Would need to make actual requests to follow
        # This is a placeholder for the redirect URL
        redirects.append({
            "from": request.url,
            "to": location,
            "status": response.status_code
        })
        break  # Simplified
    return redirects