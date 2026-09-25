"""
Burp Suite-style Intruder Module
Position-based fuzzing with multiple attack types: Sniper, Battering Ram, Pitchfork, Cluster Bomb
"""
import asyncio
import itertools
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable, AsyncGenerator
from enum import Enum
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json


class AttackType(Enum):
    SNIPER = "sniper"           # One position at a time, each payload
    BATTERING_RAM = "battering_ram"  # All positions same payload
    PITCHFORK = "pitchfork"     # Multiple positions, parallel payload lists
    CLUSTER_BOMB = "cluster_bomb"  # All combinations of payloads


@dataclass
class IntruderPosition:
    name: str
    start: int
    end: int
    value: str = ""


@dataclass
class IntruderRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: str
    positions: List[IntruderPosition] = field(default_factory=list)


@dataclass
class IntruderResult:
    request: IntruderRequest
    payload: str
    position: str
    status_code: int
    response_headers: Dict[str, str]
    response_body: str
    response_time: float
    response_length: int
    error: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


class Intruder:
    def __init__(self, http_client: httpx.AsyncClient = None, max_concurrent: int = 10):
        self.http_client = http_client
        self.max_concurrent = max_concurrent
        self._results: List[IntruderResult] = []
        self._callbacks: List[Callable] = []
        self._stop_requested = False

    def set_http_client(self, client: httpx.AsyncClient):
        self.http_client = client

    def add_callback(self, callback: Callable[[IntruderResult], None]):
        self._callbacks.append(callback)

    def stop(self):
        self._stop_requested = True

    def _apply_payloads(self, base_request: IntruderRequest, payloads: List[str], 
                       attack_type: AttackType, position_payloads: Dict[str, List[str]] = None) -> List[IntruderRequest]:
        requests = []
        
        if attack_type == AttackType.SNIPER:
            for pos in base_request.positions:
                for payload in payloads:
                    req = self._build_request(base_request, {pos.name: payload})
                    requests.append(req)
                    
        elif attack_type == AttackType.BATTERING_RAM:
            for payload in payloads:
                payload_map = {pos.name: payload for pos in base_request.positions}
                req = self._build_request(base_request, payload_map)
                requests.append(req)
                
        elif attack_type == AttackType.PITCHFORK:
            if not position_payloads:
                position_payloads = {pos.name: payloads for pos in base_request.positions}
            max_len = max(len(v) for v in position_payloads.values())
            for i in range(max_len):
                payload_map = {}
                for pos in base_request.positions:
                    pos_payloads = position_payloads.get(pos.name, payloads)
                    payload_map[pos.name] = pos_payloads[i % len(pos_payloads)]
                req = self._build_request(base_request, payload_map)
                requests.append(req)
                
        elif attack_type == AttackType.CLUSTER_BOMB:
            if not position_payloads:
                position_payloads = {pos.name: payloads for pos in base_request.positions}
            pos_names = list(position_payloads.keys())
            for combo in itertools.product(*[position_payloads[name] for name in pos_names]):
                payload_map = dict(zip(pos_names, combo))
                req = self._build_request(base_request, payload_map)
                requests.append(req)
                
        return requests

    def _build_request(self, base: IntruderRequest, payload_map: Dict[str, str]) -> IntruderRequest:
        url = base.url
        body = base.body
        headers = base.headers.copy()
        
        # Replace in URL query params
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for pos in base.positions:
            if pos.name in payload_map:
                if pos.name in query:
                    query[pos.name] = [payload_map[pos.name]]
        new_query = urlencode(query, doseq=True)
        url = urlunparse(parsed._replace(query=new_query))
        
        # Replace in body (form data or JSON)
        if body:
            content_type = headers.get("content-type", "").lower()
            if "application/json" in content_type:
                try:
                    json_body = json.loads(body)
                    for pos in base.positions:
                        if pos.name in payload_map:
                            if pos.name in json_body:
                                json_body[pos.name] = payload_map[pos.name]
                    body = json.dumps(json_body)
                except:
                    pass
            elif "application/x-www-form-urlencoded" in content_type:
                form_data = parse_qs(body)
                for pos in base.positions:
                    if pos.name in payload_map:
                        if pos.name in form_data:
                            form_data[pos.name] = [payload_map[pos.name]]
                body = urlencode(form_data, doseq=True)
            else:
                # Raw body replacement
                for pos in base.positions:
                    if pos.name in payload_map:
                        body = body.replace(pos.value, payload_map[pos.name])
        
        # Replace in headers
        for pos in base.positions:
            if pos.name in payload_map:
                for k, v in headers.items():
                    if pos.value in v:
                        headers[k] = v.replace(pos.value, payload_map[pos.name])
        
        return IntruderRequest(
            method=base.method,
            url=url,
            headers=headers,
            body=body,
            positions=base.positions
        )

    async def _send_request(self, request: IntruderRequest, payload: str, position: str) -> IntruderResult:
        if not self.http_client:
            return IntruderResult(
                request=request, payload=payload, position=position,
                status_code=0, response_headers={}, response_body="",
                response_time=0, response_length=0, error="No HTTP client"
            )
        
        start = time.time()
        try:
            kwargs = {"timeout": 30.0}
            if request.body:
                content_type = request.headers.get("content-type", "")
                if "application/json" in content_type:
                    kwargs["json"] = json.loads(request.body) if request.body else {}
                else:
                    kwargs["content"] = request.body
                    kwargs["headers"] = request.headers
            else:
                kwargs["headers"] = request.headers
                
            if request.method == "GET":
                resp = await self.http_client.get(request.url, **kwargs)
            elif request.method == "POST":
                resp = await self.http_client.post(request.url, **kwargs)
            elif request.method == "PUT":
                resp = await self.http_client.put(request.url, **kwargs)
            elif request.method == "DELETE":
                resp = await self.http_client.delete(request.url, **kwargs)
            elif request.method == "PATCH":
                resp = await self.http_client.patch(request.url, **kwargs)
            elif request.method == "HEAD":
                resp = await self.http_client.head(request.url, **kwargs)
            elif request.method == "OPTIONS":
                resp = await self.http_client.options(request.url, **kwargs)
            else:
                raise ValueError(f"Unsupported method: {request.method}")
            
            response_time = time.time() - start
            return IntruderResult(
                request=request,
                payload=payload,
                position=position,
                status_code=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.text,
                response_time=response_time,
                response_length=len(resp.content)
            )
        except Exception as e:
            response_time = time.time() - start
            return IntruderResult(
                request=request,
                payload=payload,
                position=position,
                status_code=0,
                response_headers={},
                response_body="",
                response_time=response_time,
                response_length=0,
                error=str(e)
            )

    async def attack(self, base_request: IntruderRequest, payloads: List[str],
                    attack_type: AttackType = AttackType.SNIPER,
                    position_payloads: Dict[str, List[str]] = None) -> AsyncGenerator[IntruderResult, None]:
        self._stop_requested = False
        self._results = []
        
        requests = self._apply_payloads(base_request, payloads, attack_type, position_payloads)
        
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def limited_send(req, payload, pos):
            async with semaphore:
                if self._stop_requested:
                    return None
                result = await self._send_request(req, payload, pos)
                self._results.append(result)
                for cb in self._callbacks:
                    try:
                        cb(result)
                    except:
                        pass
                return result
        
        tasks = []
        for req in requests:
            # Determine which payload was used for this request
            used_payload = ""
            for pos in req.positions:
                if pos.name in [p.name for p in base_request.positions]:
                    used_payload = getattr(pos, '_payload_used', '')
                    break
            tasks.append(limited_send(req, used_payload, ""))
        
        for coro in asyncio.as_completed(tasks):
            result = await coro
            if result:
                yield result
            if self._stop_requested:
                break

    def get_results(self) -> List[IntruderResult]:
        return self._results

    def filter_results(self, 
                       status_codes: List[int] = None,
                       min_length: int = None,
                       max_length: int = None,
                       regex_pattern: str = None,
                       grep_match: str = None,
                       grep_exclude: str = None) -> List[IntruderResult]:
        results = self._results
        
        if status_codes:
            results = [r for r in results if r.status_code in status_codes]
        if min_length is not None:
            results = [r for r in results if r.response_length >= min_length]
        if max_length is not None:
            results = [r for r in results if r.response_length <= max_length]
        if grep_match:
            results = [r for r in results if grep_match in r.response_body]
        if grep_exclude:
            results = [r for r in results if grep_exclude not in r.response_body]
        if regex_pattern:
            import re
            pattern = re.compile(regex_pattern)
            results = [r for r in results if pattern.search(r.response_body)]
            
        return results


def parse_burp_request(raw_request: str) -> IntruderRequest:
    """Parse a raw HTTP request (Burp-style) into IntruderRequest"""
    lines = raw_request.strip().split('\n')
    if not lines:
        raise ValueError("Empty request")
    
    # Parse request line
    request_line = lines[0].strip()
    parts = request_line.split(' ')
    if len(parts) != 3:
        raise ValueError(f"Invalid request line: {request_line}")
    method, path, version = parts
    
    # Parse headers
    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == '':
            body_start = i + 1
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # Parse body
    body = '\n'.join(lines[body_start:]) if body_start < len(lines) else ''
    
    # Reconstruct full URL
    host = headers.get('Host', '')
    scheme = 'https' if headers.get('X-Forwarded-Proto') == 'https' or 'https' in host else 'http'
    url = f"{scheme}://{host}{path}"
    
    return IntruderRequest(
        method=method,
        url=url,
        headers=headers,
        body=body
    )