"""
Burp Suite-style Comparer Module
Visual diff tool for comparing responses, requests, or any text data
"""
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
import difflib
import re


class DiffType(Enum):
    WORDS = "words"
    LINES = "lines"
    CHARS = "chars"


@dataclass
class DiffResult:
    similarity: float
    additions: int
    deletions: int
    changes: int
    diff_blocks: List[Dict[str, Any]]
    unified_diff: str


class Comparer:
    @staticmethod
    def compare(text1: str, text2: str, diff_type: DiffType = DiffType.LINES) -> DiffResult:
        """Compare two texts and return detailed diff"""
        if diff_type == DiffType.LINES:
            seq1 = text1.splitlines(keepends=True)
            seq2 = text2.splitlines(keepends=True)
        elif diff_type == DiffType.WORDS:
            seq1 = re.findall(r'\S+|\s+', text1)
            seq2 = re.findall(r'\S+|\s+', text2)
        else:  # CHARS
            seq1 = list(text1)
            seq2 = list(text2)
        
        matcher = difflib.SequenceMatcher(None, seq1, seq2)
        similarity = matcher.ratio()
        
        additions = 0
        deletions = 0
        changes = 0
        diff_blocks = []
        
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == 'equal':
                continue
            elif tag == 'replace':
                changes += 1
                diff_blocks.append({
                    "type": "change",
                    "old_start": i1, "old_end": i2,
                    "new_start": j1, "new_end": j2,
                    "old_text": ''.join(seq1[i1:i2]),
                    "new_text": ''.join(seq2[j1:j2])
                })
            elif tag == 'delete':
                deletions += 1
                diff_blocks.append({
                    "type": "delete",
                    "old_start": i1, "old_end": i2,
                    "new_start": j1, "new_end": j2,
                    "old_text": ''.join(seq1[i1:i2]),
                    "new_text": ""
                })
            elif tag == 'insert':
                additions += 1
                diff_blocks.append({
                    "type": "insert",
                    "old_start": i1, "old_end": i2,
                    "new_start": j1, "new_end": j2,
                    "old_text": "",
                    "new_text": ''.join(seq2[j1:j2])
                })
        
        # Generate unified diff
        unified = '\n'.join(difflib.unified_diff(
            text1.splitlines(keepends=True),
            text2.splitlines(keepends=True),
            lineterm=''
        ))
        
        return DiffResult(
            similarity=similarity,
            additions=additions,
            deletions=deletions,
            changes=changes,
            diff_blocks=diff_blocks,
            unified_diff=unified
        )
    
    @staticmethod
    def compare_bytes(bytes1: bytes, bytes2: bytes) -> DiffResult:
        """Compare binary data"""
        # Convert to hex for comparison
        hex1 = bytes1.hex()
        hex2 = bytes2.hex()
        return Comparer.compare(hex1, hex2, DiffType.CHARS)
    
    @staticmethod
    def compare_json(json1: dict, json2: dict) -> DiffResult:
        """Compare JSON objects with semantic awareness"""
        import json
        text1 = json.dumps(json1, indent=2, sort_keys=True)
        text2 = json.dumps(json2, indent=2, sort_keys=True)
        return Comparer.compare(text1, text2, DiffType.LINES)
    
    @staticmethod
    def compare_headers(headers1: Dict, headers2: Dict) -> DiffResult:
        """Compare HTTP headers"""
        # Normalize headers (lowercase keys)
        norm1 = {k.lower(): v for k, v in headers1.items()}
        norm2 = {k.lower(): v for k, v in headers2.items()}
        
        all_keys = sorted(set(norm1.keys()) | set(norm2.keys()))
        
        lines1 = [f"{k}: {norm1.get(k, '')}" for k in all_keys]
        lines2 = [f"{k}: {norm2.get(k, '')}" for k in all_keys]
        
        return Comparer.compare('\n'.join(lines1), '\n'.join(lines2), DiffType.LINES)
    
    @staticmethod
    def find_reflected_input(response_body: str, input_value: str, context_chars: int = 50) -> List[Dict]:
        """Find all occurrences of input in response with context"""
        results = []
        input_lower = input_value.lower()
        body_lower = response_body.lower()
        
        start = 0
        while True:
            idx = body_lower.find(input_lower, start)
            if idx == -1:
                break
            
            # Get context
            ctx_start = max(0, idx - context_chars)
            ctx_end = min(len(response_body), idx + len(input_value) + context_chars)
            context = response_body[ctx_start:ctx_end]
            
            # Determine context type
            ctx_before = response_body[max(0, idx-100):idx]
            ctx_after = response_body[idx+len(input_value):idx+len(input_value)+100]
            
            context_type = "unknown"
            if '<script' in ctx_before.lower() or '</script' in ctx_before.lower():
                context_type = "javascript"
            elif 'href=' in ctx_before.lower() or 'src=' in ctx_before.lower() or 'action=' in ctx_before.lower():
                context_type = "attribute"
            elif '<' in ctx_before[-20:] and '>' in ctx_after[:20]:
                context_type = "html_tag"
            elif '{' in ctx_before[-10:] or '}}' in ctx_after[:10]:
                context_type = "template"
            elif 'value=' in ctx_before.lower():
                context_type = "form_value"
            
            results.append({
                "position": idx,
                "context": context,
                "context_type": context_type,
                "before": ctx_before[-50:],
                "after": ctx_after[:50]
            })
            
            start = idx + 1
        
        return results
    
    @staticmethod
    def extract_forms(html: str) -> List[Dict]:
        """Extract all forms from HTML"""
        forms = []
        # Simple regex-based extraction (for more robust parsing, use BeautifulSoup)
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            inputs = []
            for inp_match in input_pattern.finditer(form_html):
                inp_html = inp_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                value_match = re.search(r'value=["\']([^"\']*)["\']', inp_html, re.IGNORECASE)
                
                inputs.append({
                    "name": name_match.group(1) if name_match else "",
                    "type": type_match.group(1) if type_match else "text",
                    "value": value_match.group(1) if value_match else ""
                })
            
            forms.append({
                "action": action_match.group(1) if action_match else "",
                "method": method_match.group(1).upper() if method_match else "GET",
                "inputs": inputs,
                "raw_html": form_html[:500]
            })
        
        return forms
    
    @staticmethod
    def extract_links(html: str, base_url: str = "") -> List[Dict]:
        """Extract all links from HTML"""
        from urllib.parse import urljoin
        links = []
        link_pattern = re.compile(r'<a\s+[^>]*href=["\']([^"\']*)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        
        for match in link_pattern.finditer(html):
            href = match.group(1)
            text = re.sub(r'<[^>]+>', '', match.group(2)).strip()
            full_url = urljoin(base_url, href) if base_url else href
            links.append({
                "href": href,
                "full_url": full_url,
                "text": text[:200]
            })
        return links
    
    @staticmethod
    def extract_scripts(html: str) -> List[Dict]:
        """Extract script sources and inline scripts"""
        scripts = []
        src_pattern = re.compile(r'<script\s+src=["\']([^"\']*)["\']', re.IGNORECASE)
        inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
        
        for match in src_pattern.finditer(html):
            scripts.append({
                "type": "external",
                "src": match.group(1),
                "content": ""
            })
        
        for match in inline_pattern.finditer(html):
            content = match.group(1).strip()
            if content:
                scripts.append({
                    "type": "inline",
                    "src": "",
                    "content": content[:1000]
                })
        return scripts
    
    @staticmethod
    def extract_comments(html: str) -> List[str]:
        """Extract HTML comments"""
        return re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    
    @staticmethod
    def extract_hidden_inputs(html: str) -> List[Dict]:
        """Extract hidden form inputs (often contain tokens)"""
        hidden = []
        pattern = re.compile(r'<input[^>]*type=["\']hidden["\'][^>]*>', re.IGNORECASE)
        
        for match in pattern.finditer(html):
            inp = match.group(0)
            name_match = re.search(r'name=["\']([^"\']*)["\']', inp, re.IGNORECASE)
            value_match = re.search(r'value=["\']([^"\']*)["\']', inp, re.IGNORECASE)
            id_match = re.search(r'id=["\']([^"\']*)["\']', inp, re.IGNORECASE)
            
            hidden.append({
                "name": name_match.group(1) if name_match else "",
                "id": id_match.group(1) if id_match else "",
                "value": value_match.group(1) if value_match else "",
                "raw": inp
            })
        return hidden


# Visual diff formatter for terminal/HTML output
class DiffFormatter:
    @staticmethod
    def to_html(diff: DiffResult, text1: str, text2: str) -> str:
        """Format diff as HTML with colors"""
        html = ['<div class="diff-container">']
        
        # Summary
        html.append(f'<div class="diff-summary">')
        html.append(f'Similarity: {diff.similarity:.1%} | ')
        html.append(f'Additions: <span class="add">{diff.additions}</span> | ')
        html.append(f'Deletions: <span class="del">{diff.deletions}</span> | ')
        html.append(f'Changes: <span class="chg">{diff.changes}</span>')
        html.append('</div>')
        
        # Side-by-side diff
        html.append('<div class="diff-side-by-side">')
        html.append('<div class="diff-left"><h4>Original</h4><pre>')
        
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()
        
        # Simple side-by-side using difflib
        for i, line in enumerate(lines1):
            html.append(f'<span class="line-num">{i+1}</span>{line}<br>')
        html.append('</pre></div>')
        
        html.append('<div class="diff-right"><h4>Modified</h4><pre>')
        for i, line in enumerate(lines2):
            html.append(f'<span class="line-num">{i+1}</span>{line}<br>')
        html.append('</pre></div>')
        
        html.append('</div></div>')
        return '\n'.join(html)
    
    @staticmethod
    def to_ansi(diff: DiffResult, text1: str, text2: str) -> str:
        """Format diff with ANSI colors for terminal"""
        output = []
        output.append(f"\033[1mSimilarity: {diff.similarity:.1%}\033[0m")
        output.append(f"Additions: \033[32m{diff.additions}\033[0m | Deletions: \033[31m{diff.deletions}\033[0m | Changes: \033[33m{diff.changes}\033[0m")
        output.append("-" * 60)
        
        for block in diff.diff_blocks:
            if block["type"] == "change":
                output.append(f"\033[33m~\033[0m Line {block['old_start']+1}:")
                output.append(f"  \033[31m-{block['old_text'][:80]}\033[0m")
                output.append(f"  \033[32m+{block['new_text'][:80]}\033[0m")
            elif block["type"] == "delete":
                output.append(f"\033[31m-\033[0m Line {block['old_start']+1}: {block['old_text'][:80]}")
            elif block["type"] == "insert":
                output.append(f"\033[32m+\033[0m Line {block['new_start']+1}: {block['new_text'][:80]}")
        
        return '\n'.join(output)