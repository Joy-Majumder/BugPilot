"""
Burp Suite-style Sequencer Module
Token/session entropy analysis and randomness testing
"""
import math
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from collections import Counter
import re
import asyncio
import httpx
from urllib.parse import urlparse, parse_qs


@dataclass
class TokenSample:
    value: str
    timestamp: float
    source: str  # "cookie", "header", "body", "url"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EntropyAnalysis:
    token_name: str
    sample_count: int
    token_length: int
    charset_size: int
    bits_per_character: float
    total_entropy_bits: float
    character_frequencies: Dict[str, int]
    chi_square: float
    chi_square_p_value: float
    monte_carlo_pi: float
    serial_correlation: float
    mean: float
    std_dev: float
    min_entropy: float
    max_entropy: float
    overall_score: str  # "Excellent", "Good", "Fair", "Poor", "Critical"


class Sequencer:
    def __init__(self, http_client: httpx.AsyncClient = None):
        self.http_client = http_client
        self.samples: List[TokenSample] = []
    
    def set_http_client(self, client: httpx.AsyncClient):
        self.http_client = client
    
    def add_sample(self, value: str, source: str, timestamp: float = None, metadata: Dict = None):
        import time
        self.samples.append(TokenSample(
            value=value,
            timestamp=timestamp or time.time(),
            source=source,
            metadata=metadata or {}
        ))
    
    def add_samples(self, values: List[str], source: str):
        import time
        base_time = time.time()
        for i, v in enumerate(values):
            self.add_sample(v, source, base_time + i * 0.001)
    
    def extract_from_cookies(self, cookie_header: str, name_pattern: str = None) -> List[str]:
        """Extract token values from Cookie header"""
        tokens = []
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                name, value = cookie.split('=', 1)
                if not name_pattern or re.search(name_pattern, name, re.I):
                    tokens.append(value.strip())
        return tokens
    
    def extract_from_headers(self, headers: Dict, name_pattern: str = None) -> List[str]:
        """Extract token values from headers"""
        tokens = []
        for k, v in headers.items():
            if not name_pattern or re.search(name_pattern, k, re.I):
                # Try to extract token-like values
                if len(v) > 8:  # Minimum token length
                    tokens.append(v)
        return tokens
    
    async def collect_samples_from_endpoint(self, 
                                            url: str, 
                                            method: str = "GET",
                                            headers: Dict = None,
                                            cookies: Dict = None,
                                            param_name: str = None,
                                            count: int = 100,
                                            delay: float = 0.1) -> List[str]:
        """Collect token samples by repeatedly hitting an endpoint"""
        if not self.http_client:
            raise ValueError("No HTTP client configured")
        
        tokens = []
        headers = headers or {}
        cookies = cookies or {}
        
        for i in range(count):
            try:
                if method == "GET":
                    resp = await self.http_client.get(url, headers=headers, cookies=cookies, timeout=10)
                elif method == "POST":
                    data = {}
                    if param_name:
                        data[param_name] = "test"
                    resp = await self.http_client.post(url, data=data, headers=headers, cookies=cookies, timeout=10)
                else:
                    raise ValueError(f"Unsupported method: {method}")
                
                # Extract tokens from Set-Cookie
                set_cookie = resp.headers.get('Set-Cookie', '')
                if set_cookie:
                    cookie_tokens = self.extract_from_cookies(set_cookie)
                    tokens.extend(cookie_tokens)
                
                # Extract from response body (e.g., CSRF tokens in forms)
                if param_name:
                    # Look for token in response body
                    import re
                    pattern = rf'{re.escape(param_name)}["\']?\s*[:=]\s*["\']?([a-zA-Z0-9+/=_-]+)'
                    matches = re.findall(pattern, resp.text, re.I)
                    tokens.extend(matches)
                
                if i % 10 == 0:
                    await asyncio.sleep(delay)
                    
            except Exception as e:
                print(f"Error collecting sample {i}: {e}")
        
        self.add_samples(tokens, f"endpoint:{url}")
        return tokens
    
    def analyze(self, token_name: str = None, min_samples: int = 10) -> Optional[EntropyAnalysis]:
        """Analyze collected samples for entropy"""
        if token_name:
            samples = [s for s in self.samples if s.metadata.get('name') == token_name or 
                       s.source == token_name]
        else:
            samples = self.samples
        
        if len(samples) < min_samples:
            return None
        
        values = [s.value for s in samples]
        return self._analyze_values(token_name or "token", values)
    
    def _analyze_values(self, name: str, values: List[str]) -> EntropyAnalysis:
        """Core entropy analysis"""
        sample_count = len(values)
        token_length = len(values[0]) if values else 0
        
        # Character frequency analysis
        all_chars = ''.join(values)
        char_freq = Counter(all_chars)
        charset_size = len(char_freq)
        
        # Bits per character
        if charset_size > 0:
            bits_per_char = math.log2(charset_size)
        else:
            bits_per_char = 0
        
        total_entropy = token_length * bits_per_char
        
        # Chi-square test for uniform distribution
        expected_freq = sample_count * token_length / charset_size if charset_size > 0 else 0
        chi_square = sum((freq - expected_freq) ** 2 / expected_freq for freq in char_freq.values()) if expected_freq > 0 else 0
        
        # Approximate p-value (simplified)
        df = charset_size - 1
        if df > 0 and chi_square > 0:
            # Using approximation
            chi_square_p = min(1.0, max(0.0, 1.0 - chi_square / (2 * df)))
        else:
            chi_square_p = 1.0
        
        # Monte Carlo Pi estimation (using token values as random points)
        mc_pi = self._estimate_pi(values)
        
        # Serial correlation coefficient
        serial_corr = self._serial_correlation(values)
        
        # Arithmetic mean of byte values
        byte_values = [ord(c) for c in all_chars]
        mean = statistics.mean(byte_values) if byte_values else 0
        std_dev = statistics.stdev(byte_values) if len(byte_values) > 1 else 0
        
        # Min/Max entropy
        min_entropy = -math.log2(max(char_freq.values()) / (sample_count * token_length)) if char_freq else 0
        max_entropy = math.log2(charset_size) if charset_size > 0 else 0
        
        # Overall score
        overall_score = self._score_entropy(total_entropy, chi_square_p, serial_corr, charset_size, token_length)
        
        return EntropyAnalysis(
            token_name=name,
            sample_count=sample_count,
            token_length=token_length,
            charset_size=charset_size,
            bits_per_character=bits_per_char,
            total_entropy_bits=total_entropy,
            character_frequencies=dict(char_freq),
            chi_square=chi_square,
            chi_square_p_value=chi_square_p,
            monte_carlo_pi=mc_pi,
            serial_correlation=serial_corr,
            mean=mean,
            std_dev=std_dev,
            min_entropy=min_entropy,
            max_entropy=max_entropy,
            overall_score=overall_score
        )
    
    def _estimate_pi(self, values: List[str]) -> float:
        """Estimate Pi using token values as random coordinates"""
        points_inside = 0
        total_points = 0
        
        for val in values:
            # Convert token to coordinate pairs
            for i in range(0, len(val) - 1, 2):
                try:
                    x = (ord(val[i]) % 256) / 255.0
                    y = (ord(val[i+1]) % 256) / 255.0
                    if x*x + y*y <= 1.0:
                        points_inside += 1
                    total_points += 1
                except:
                    pass
        
        if total_points == 0:
            return 0.0
        return 4.0 * points_inside / total_points
    
    def _serial_correlation(self, values: List[str]) -> float:
        """Calculate serial correlation between consecutive tokens"""
        if len(values) < 2:
            return 0.0
        
        # Convert to numeric sequences
        all_bytes = [ord(c) for v in values for c in v]
        if len(all_bytes) < 2:
            return 0.0
        
        # Lag-1 autocorrelation
        n = len(all_bytes)
        mean = sum(all_bytes) / n
        numerator = sum((all_bytes[i] - mean) * (all_bytes[i+1] - mean) for i in range(n-1))
        denominator = sum((x - mean) ** 2 for x in all_bytes)
        
        if denominator == 0:
            return 0.0
        return numerator / denominator
    
    def _score_entropy(self, total_bits: float, chi_p: float, serial_corr: float, 
                       charset_size: int, length: int) -> str:
        """Score entropy quality"""
        score = 0
        
        # Entropy bits scoring
        if total_bits >= 128:
            score += 3
        elif total_bits >= 64:
            score += 2
        elif total_bits >= 32:
            score += 1
        
        # Chi-square p-value (higher = more random)
        if chi_p > 0.05:
            score += 2
        elif chi_p > 0.01:
            score += 1
        
        # Serial correlation (closer to 0 = better)
        if abs(serial_corr) < 0.01:
            score += 2
        elif abs(serial_corr) < 0.05:
            score += 1
        
        # Charset diversity
        if charset_size >= 64:
            score += 2
        elif charset_size >= 32:
            score += 1
        
        # Length adequacy
        if length >= 32:
            score += 1
        
        if score >= 9:
            return "Excellent"
        elif score >= 7:
            return "Good"
        elif score >= 5:
            return "Fair"
        elif score >= 3:
            return "Poor"
        return "Critical"
    
    def get_prediction_difficulty(self, analysis: EntropyAnalysis) -> Dict[str, Any]:
        """Estimate difficulty of predicting next token"""
        entropy = analysis.total_entropy_bits
        
        # Brute force time estimates (assuming 1000 req/sec)
        guesses_per_sec = 1000
        
        return {
            "entropy_bits": entropy,
            "guesses_needed": 2 ** entropy,
            "time_at_1k_sec": (2 ** entropy) / guesses_per_sec if entropy < 100 else "infeasible",
            "time_at_1M_sec": (2 ** entropy) / 1_000_000 if entropy < 100 else "infeasible",
            "practical_bruteforce": entropy < 40,
            "recommendation": self._get_recommendation(analysis)
        }
    
    def _get_recommendation(self, analysis: EntropyAnalysis) -> str:
        if analysis.overall_score == "Critical":
            return "Token is predictable. Immediate rotation and generator replacement required."
        elif analysis.overall_score == "Poor":
            return "Token has low entropy. Increase length and charset. Review generation algorithm."
        elif analysis.overall_score == "Fair":
            return "Token entropy is acceptable but could be improved. Consider longer tokens."
        elif analysis.overall_score == "Good":
            return "Token entropy is good. Monitor for any pattern changes."
        return "Token entropy is excellent. No action needed."
    
    def clear(self):
        self.samples.clear()


# JWT-specific analysis
def analyze_jwt(jwt_token: str) -> Dict[str, Any]:
    """Analyze JWT token structure and security"""
    import base64
    import json
    
    parts = jwt_token.split('.')
    if len(parts) != 3:
        return {"error": "Invalid JWT format"}
    
    try:
        # Decode header
        header_b64 = parts[0] + '=' * (-len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # Decode payload
        payload_b64 = parts[1] + '=' * (-len(parts[1]) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Analyze
        issues = []
        alg = header.get('alg', '').lower()
        
        if alg == 'none':
            issues.append({"severity": "Critical", "issue": "Algorithm 'none' - allows signature bypass"})
        elif alg.startswith('hs'):
            issues.append({"severity": "Medium", "issue": f"HMAC algorithm ({alg}) - vulnerable to key cracking if weak secret"})
        elif alg.startswith('rs') or alg.startswith('es'):
            issues.append({"severity": "Info", "issue": f"Asymmetric algorithm ({alg}) - verify key management"})
        
        if 'kid' in header:
            issues.append({"severity": "Info", "issue": f"Key ID present: {header['kid']} - check for SQLi/path traversal"})
        
        if 'exp' not in payload:
            issues.append({"severity": "Medium", "issue": "No expiration claim (exp)"})
        
        if 'iat' not in payload:
            issues.append({"severity": "Low", "issue": "No issued-at claim (iat)"})
        
        return {
            "header": header,
            "payload": payload,
            "signature_present": len(parts[2]) > 0,
            "issues": issues,
            "raw_parts": parts
        }
    except Exception as e:
        return {"error": f"Failed to parse JWT: {e}"}